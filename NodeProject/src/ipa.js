import {promises as fsPromises} from 'fs';
import os from 'os';
import {createCipheriv, createDecipheriv, createHash, randomBytes} from 'crypto';
import path from 'path';
import {Store} from './client.js';
import {appPriceInfo, storefrontCurrentVersion} from './catalog.js';

function versionIdentifiersFromSong(song) {
    const metadata = song?.metadata || {};
    const candidates = [
        metadata.softwareVersionExternalIdentifiers,
        song?.softwareVersionExternalIdentifiers,
        metadata.softwareVersionExternalIdentifier,
        song?.softwareVersionExternalIdentifier,
    ];
    const result = [];
    const seen = new Set();
    const append = (value) => {
        if (Array.isArray(value)) {
            value.forEach(append);
            return;
        }
        if (value && typeof value === 'object') {
            append(value.softwareVersionExternalIdentifier ?? value.externalVersionId ?? value.versionId ?? value.id);
            return;
        }
        const id = String(value ?? '').trim();
        if (!/^\d+$/.test(id) || seen.has(id)) return;
        seen.add(id);
        result.push(id);
    };
    candidates.forEach(append);
    return result;
}
import {readCookieJar, restoreCookieJar} from './gsa.js';
import {SignatureClient} from './Signature.js';
import {download} from './downloader.js';
import {t} from './i18n.js';

const DEFAULT_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const SESSION_TTL_MS = Number(process.env.IPA_SESSION_TTL_MS || DEFAULT_SESSION_TTL_MS);
const SESSION_FLOW_VERSION = 'appstore-direct-v1';
const ACCEPTED_SESSION_FLOW_VERSIONS = new Set([SESSION_FLOW_VERSION, 'gsa-srp-v10']);
const ENCRYPTED_SESSION_FORMAT = 'pastel-session-aes-gcm-v1';

function decodeSessionKey(value) {
    if (!value) return null;
    const key = Buffer.from(String(value), 'base64');
    return key.length === 32 ? key : null;
}

function sealSession(session, keyValue) {
    const key = Buffer.isBuffer(keyValue) ? keyValue : decodeSessionKey(keyValue);
    if (!key) throw new Error('A 256-bit session encryption key is required');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([
        cipher.update(JSON.stringify(session), 'utf8'),
        cipher.final(),
    ]);
    return {
        format: ENCRYPTED_SESSION_FORMAT,
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
        ciphertext: ciphertext.toString('base64'),
    };
}

function openSession(envelope, keyValue) {
    const key = Buffer.isBuffer(keyValue) ? keyValue : decodeSessionKey(keyValue);
    if (!key || envelope?.format !== ENCRYPTED_SESSION_FORMAT) return null;
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
        decipher.final(),
    ]);
    return JSON.parse(plaintext.toString('utf8'));
}

function appSupportDir() {
    if (process.env.IPA_SESSION_DIR) return process.env.IPA_SESSION_DIR;
    if (process.platform === 'darwin') {
        return path.join(os.homedir(), 'Library', 'Application Support', 'IPA Download', 'sessions');
    }
    if (process.platform === 'win32') {
        return path.join(process.env.APPDATA || os.homedir(), 'IPA Download', 'sessions');
    }
    return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'IPA Download', 'sessions');
}

function sessionFileFor(email) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const digest = createHash('sha256').update(normalizedEmail).digest('hex');
    return path.join(appSupportDir(), `${digest}.json`);
}

function validSessionFor(email, session) {
    if (!session || typeof session !== 'object') return false;
    if (!ACCEPTED_SESSION_FLOW_VERSIONS.has(session.flowVersion)) return false;
    if (String(session.appleAccount || '').trim().toLowerCase() !== String(email || '').trim().toLowerCase()) return false;
    const savedAt = Number(session.savedAt);
    if (!Number.isFinite(savedAt) || savedAt <= 0) return false;
    if (SESSION_TTL_MS > 0 && Date.now() - savedAt > SESSION_TTL_MS) return false;
    const authHeaders = session.user?.authHeaders;
    return Boolean(authHeaders?.['X-Token'] && authHeaders?.['X-Dsid']);
}

export class Ipa {
    constructor({APPLE_ID, PASSWORD, CODE, SESSION_KEY = ''}) {
        this.creds = {APPLE_ID, PASSWORD, CODE};
        this.sessionEncryptionKey = decodeSessionKey(SESSION_KEY);
        this.user = null;
        this.auth = {};
        this.dir = '.';
        this.out = '';
        this.cache = '';
        this.sessionFile = sessionFileFor(APPLE_ID);
        this.usedCachedSession = false;
    }

    async loadSessionEntry() {
        try {
            const raw = await fsPromises.readFile(this.sessionFile, 'utf8');
            const stored = JSON.parse(raw);
            if (stored?.format === ENCRYPTED_SESSION_FORMAT) {
                return openSession(stored, this.sessionEncryptionKey);
            }

            // One-time migration from the historical plaintext JSON format.
            // A key must be supplied through the anonymous stdin pipe; otherwise
            // plaintext sessions are deliberately ignored.
            if (!this.sessionEncryptionKey) return null;
            await this.writeEncryptedSession(stored);
            return stored;
        } catch {
            return null;
        }
    }

    async loadSession() {
        const session = await this.loadSessionEntry();
        if (!validSessionFor(this.creds.APPLE_ID, session)) return null;
        return session.user;
    }

    async saveSession(user) {
        const session = {
            appleAccount: String(this.creds.APPLE_ID || '').trim().toLowerCase(),
            flowVersion: SESSION_FLOW_VERSION,
            savedAt: Date.now(),
            user: {
                accountInfo: user.accountInfo,
                dsPersonId: user.dsPersonId,
                pod: user.pod || '',
                authHeaders: user.authHeaders,
                cookieText: user.cookieText || '',
            }
        };
        await this.writeEncryptedSession(session);
    }

    async writeEncryptedSession(session) {
        if (!this.sessionEncryptionKey) return;
        const envelope = sealSession(session, this.sessionEncryptionKey);
        await fsPromises.mkdir(path.dirname(this.sessionFile), {recursive: true, mode: 0o700});
        const temporaryFile = `${this.sessionFile}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
        try {
            await fsPromises.writeFile(temporaryFile, JSON.stringify(envelope), {mode: 0o600});
            await fsPromises.rename(temporaryFile, this.sessionFile);
        } finally {
            await fsPromises.rm(temporaryFile, {force: true}).catch(() => {});
        }
    }

    async clearSession() {
        await fsPromises.rm(this.sessionFile, {force: true}).catch(() => {});
        this.usedCachedSession = false;
    }

    applyUser(user, usedCachedSession) {
        this.user = user;
        this.auth = {
            authHeaders: user.authHeaders,
            pod: user.pod || '',
            cookieJar: restoreCookieJar(user.cookieText, this.creds.APPLE_ID),
        };
        this.usedCachedSession = usedCachedSession;
    }

    async login({force = false} = {}) {
        const previousSessionEntry = await this.loadSessionEntry();
        const previousSession = previousSessionEntry?.user || null;
        if (!force) {
            const cachedUser = validSessionFor(this.creds.APPLE_ID, previousSessionEntry) ? previousSession : null;
            if (cachedUser) {
                console.log(t('login_local_session', {id: this.creds.APPLE_ID}));
                this.applyUser(cachedUser, true);
                return;
            }
        }

        const user = await Store.login(this.creds.APPLE_ID, this.creds.PASSWORD, this.creds.CODE, previousSession);
        console.log(t('login_success', {name: `${user.accountInfo.address.firstName} ${user.accountInfo.address.lastName}`}));
        this.applyUser(user, false);
        await this.saveSession(user).catch(error => {
            console.log(t('save_session_failed', {message: error.message}));
        });
    }

    async persistCurrentSession() {
        if (!this.user) return;
        const cookieText = readCookieJar(this.auth.cookieJar);
        if (cookieText) this.user.cookieText = cookieText;
        await this.saveSession(this.user);
    }

    async info(APPID, appVerId) {
        const appInfo = await Store.AppInfo(APPID, appVerId, this.auth);
        const s = appInfo?.songList?.[0];
        const name = s?.metadata?.bundleDisplayName || 'UnknownApp';
        const ver = s?.metadata?.bundleShortVersionString || 'UnknownVer';
        console.log(t('app_info', {name, ver}));
        const noUpdateSuffix = process.env.IPA_REMOVE_APP_STORE_UPDATE_METADATA === '1' ? '_no-update' : '';
        this.out = path.join(this.dir, `${name}_${ver}${noUpdateSuffix}.ipa`);
        return s;
    }

    // 判断 App 是否免费：优先用上层（App 界面）传入的价格信号，未知时用 iTunes lookup 兜底。
    // 仅免费 App 才允许主动申请购买许可；付费 App 一律不触发购买（已购买的会直接命中 AppInfo）。
    async isFreeApp(APPID) {
        const flag = process.env.IPA_APP_IS_FREE;
        if (flag === '1') return true;
        if (flag === '0') return false;
        const info = await appPriceInfo(APPID, {country: process.env.IPA_APP_COUNTRY || 'us'});
        // lookup 不可用（地区差异等）时按「免费」处理，保持免费 App 可用；付费 App 仍会在 buyProduct 阶段被 Apple 拒绝、不会扣费。
        return info ? info.isFree : true;
    }

    // 从 Apple 官方元数据获取该 App 的全部历史版本 ID（外部版本标识）。
    // 用于第三方来源不可用时的兜底：登录后读取 softwareVersionExternalIdentifiers。
    async listVersionIds(APPID) {
        if (!this.user) throw new Error('Please login() first');
        return await this._withReauth(() => this._listVersionIdsOnce(APPID));
    }

    async _listVersionIdsOnce(APPID) {
        // 先直接查（已购买 / 已获取过的 App 无需再申请许可，不产生任何副作用）。
        let song = await Store.AppInfo(APPID, '', this.auth, {listVersions: true}).catch(error => ({_error: error}));
        if (song?._error) {
            // 用稳定的 error.code 判断「缺少许可」，不依赖文案语言；Apple 自身英文消息保留兜底。
            const noLicense = song._error.code === 'LICENSE_NOT_FOUND'
                || song._error.code === 'APPINFO_EMPTY'
                || /License not found/i.test(song._error.message || '');
            if (!noLicense) throw song._error;
            // 缺少许可：仅免费 App 才主动申请；付费且未购买的 App 直接报错、绝不触发购买。
            if (!(await this.isFreeApp(APPID))) {
                throw new Error(t('paid_not_purchased'));
            }
            if (process.env.IPA_ALLOW_APP_ACQUIRE !== '1') {
                return {
                    appId: String(APPID),
                    requiresAcquisition: true,
                    versionIds: [],
                };
            }
            await Store.purchase(APPID, '', this.auth);
            // Apple 的购买许可会延迟几秒才在 volumeStoreDownloadProduct 可见。
            // 立即只查一次会把已成功获取的 App 误报为“没有数据”。
            let lastError;
            for (const delayMs of [350, 800, 1600, 3000]) {
                await new Promise(resolve => setTimeout(resolve, delayMs));
                try {
                    song = await Store.AppInfo(APPID, '', this.auth, {listVersions: true});
                    lastError = null;
                    break;
                } catch (error) {
                    lastError = error;
                    if (error.code !== 'LICENSE_NOT_FOUND' && error.code !== 'APPINFO_EMPTY') throw error;
                }
            }
            if (lastError) {
                const fallback = await storefrontCurrentVersion(APPID, {
                    country: process.env.IPA_APP_COUNTRY || 'us',
                });
                if (fallback) return fallback;
                throw lastError;
            }
        }
        const s = song?.songList?.[0];
        const meta = s?.metadata || {};
        const ids = versionIdentifiersFromSong(s);
        return {
            appId: String(APPID),
            name: meta.bundleDisplayName || 'UnknownApp',
            latestVersion: meta.bundleShortVersionString || '',
            latestVersionId: String(meta.softwareVersionExternalIdentifier ?? (ids.length ? ids[ids.length - 1] : '')),
            versionIds: ids,
        };
    }

    async runDownload({dir = '.', APPID, appVerId} = {}) {
        if (!this.user) throw new Error('Please login() first');
        this.dir = dir;
        this.cache = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'ipa-history-download-parts-'));
        console.log(t('temp_dir', {cache: this.cache}));
        try {
            // A version download uses the license that AppInfo already verifies.
            // Calling buyProduct again here is unnecessary and breaks existing
            // licenses because StoreServices commonly answers a repeated request
            // with failureType 5002 and a generic “unknown error” message.
            // New free Apps are acquired explicitly by listVersionIds() only
            // after the user confirms the acquisition prompt.
            const song = await this.info(APPID, appVerId);
            const res = await download(song.URL, this.out, this.cache, this.auth.authHeaders || {});
            console.log(t('download_complete', {mb: (res.fileSize / 1024 / 1024).toFixed(2), parts: res.parts}));
            // 稳定的机器标记：进入「校验/签名/存档」阶段，供 App 显示「打包中」（与显示文案解耦，不随语言变化）。
            console.log('@@IPA:phase=packaging');
            const signer = new SignatureClient(song, this.user.accountInfo.appleId, {
                includeAppStoreMetadata: process.env.IPA_REMOVE_APP_STORE_UPDATE_METADATA !== '1',
            });
            await signer.sign(this.out);

            console.log(t('file_archived', {out: this.out}));
        } finally {
            await this.persistCurrentSession().catch(() => {});
            await fsPromises.rm(this.cache, {recursive: true, force: true}).catch(() => {});
            Store.cleanup?.();
            console.log(t('cleanup_done'));
        }
    }

    async run(options = {}) {
        return await this._withReauth(() => this.runDownload(options));
    }

    // 执行 fn；若失败且疑似本地缓存会话过期，则清会话、强制重新登录（可能触发 2FA）后重试一次。
    async _withReauth(fn) {
        try {
            const result = await fn();
            await this.persistCurrentSession().catch(() => {});
            return result;
        } catch (error) {
            const message = error.message || String(error);
            // 用稳定的 error.code 判断商店会话过期（cookie/令牌失效），不依赖文案语言；Apple 英文消息保留兜底。
            const code = error.code;
            const sessionMayBeExpired = this.usedCachedSession
                && (code === 'TOKEN_EXPIRED'
                    || /401|403|Your password has changed\.?|password token is expired|token|session|authenticate|authorization|Sign In to the iTunes Store/i.test(message))
                && !/License not found|已拥有|already|not found/i.test(message);
            if (!sessionMayBeExpired) throw error;

            console.log(t('relogin'));
            await this.login({force: true});
            const result = await fn();
            await this.persistCurrentSession().catch(() => {});
            return result;
        }
    }
}

export {DEFAULT_SESSION_TTL_MS, openSession, sealSession, versionIdentifiersFromSong};
