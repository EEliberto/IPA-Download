import {promises as fsPromises} from 'fs';
import os from 'os';
import {createHash} from 'crypto';
import path from 'path';
import {Store} from './client.js';
import {appPriceInfo} from './catalog.js';
import {restoreCookieJar} from './gsa.js';
import {SignatureClient} from './Signature.js';
import {download} from './downloader.js';
import {t} from './i18n.js';

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SESSION_FLOW_VERSION = 'gsa-srp-v10';

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
    if (session.flowVersion !== SESSION_FLOW_VERSION) return false;
    if (String(session.appleAccount || '').trim().toLowerCase() !== String(email || '').trim().toLowerCase()) return false;
    if (!session.savedAt || Date.now() - Number(session.savedAt) > SESSION_TTL_MS) return false;
    const authHeaders = session.user?.authHeaders;
    return Boolean(authHeaders?.['X-Token'] && authHeaders?.['X-Dsid']);
}

export class Ipa {
    constructor({APPLE_ID, PASSWORD, CODE}) {
        this.creds = {APPLE_ID, PASSWORD, CODE};
        this.user = null;
        this.auth = {};
        this.dir = '.';
        this.out = '';
        this.cache = '';
        this.sessionFile = sessionFileFor(APPLE_ID);
        this.usedCachedSession = false;
    }

    async loadSession() {
        try {
            const raw = await fsPromises.readFile(this.sessionFile, 'utf8');
            const session = JSON.parse(raw);
            if (!validSessionFor(this.creds.APPLE_ID, session)) return null;
            return session.user;
        } catch {
            return null;
        }
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
        await fsPromises.mkdir(path.dirname(this.sessionFile), {recursive: true, mode: 0o700});
        await fsPromises.writeFile(this.sessionFile, JSON.stringify(session), {mode: 0o600});
    }

    async clearSession() {
        await fsPromises.rm(this.sessionFile, {force: true}).catch(() => {});
        this.usedCachedSession = false;
    }

    async login({force = false} = {}) {
        if (!force) {
            const cachedUser = await this.loadSession();
            if (cachedUser) {
                console.log(t('login_local_session', {id: this.creds.APPLE_ID}));
                this.user = cachedUser;
                this.auth = {authHeaders: cachedUser.authHeaders, pod: cachedUser.pod || '', cookieJar: restoreCookieJar(cachedUser.cookieText)};
                this.usedCachedSession = true;
                return;
            }
        }

        const user = await Store.login(this.creds.APPLE_ID, this.creds.PASSWORD, this.creds.CODE);
        console.log(t('login_success', {name: `${user.accountInfo.address.firstName} ${user.accountInfo.address.lastName}`}));
        this.user = user;
        this.auth = {authHeaders: user.authHeaders, pod: user.pod || '', cookieJar: restoreCookieJar(user.cookieText)};
        this.usedCachedSession = false;
        await this.saveSession(user).catch(error => {
            console.log(t('save_session_failed', {message: error.message}));
        });
    }

    async info(APPID, appVerId) {
        const appInfo = await Store.AppInfo(APPID, appVerId, this.auth);
        const s = appInfo?.songList?.[0];
        const name = s?.metadata?.bundleDisplayName || 'UnknownApp';
        const ver = s?.metadata?.bundleShortVersionString || 'UnknownVer';
        console.log(t('app_info', {name, ver}));
        this.out = path.join(this.dir, `${name}_${ver}.ipa`);
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
        let song = await Store.AppInfo(APPID, '', this.auth).catch(error => ({_error: error}));
        if (song?._error) {
            // 用稳定的 error.code 判断「缺少许可」，不依赖文案语言；Apple 自身英文消息保留兜底。
            const noLicense = song._error.code === 'APPINFO_FAIL' || /License not found/i.test(song._error.message || '');
            if (!noLicense) throw song._error;
            // 缺少许可：仅免费 App 才主动申请；付费且未购买的 App 直接报错、绝不触发购买。
            if (!(await this.isFreeApp(APPID))) {
                throw new Error(t('paid_not_purchased'));
            }
            await Store.purchase(APPID, '', this.auth);
            song = await Store.AppInfo(APPID, '', this.auth);
        }
        const s = song?.songList?.[0];
        const meta = s?.metadata || {};
        const ids = Array.isArray(meta.softwareVersionExternalIdentifiers)
            ? meta.softwareVersionExternalIdentifiers.map(String)
            : [];
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
            const purchaseResult = await Store.purchase(APPID, appVerId, this.auth);
            console.log(t('purchase_ok', {message: purchaseResult.customerMessage}));
            const song = await this.info(APPID, appVerId);
            const res = await download(song.URL, this.out, this.cache, this.auth.authHeaders || {});
            console.log(t('download_complete', {mb: (res.fileSize / 1024 / 1024).toFixed(2), parts: res.parts}));
            // 稳定的机器标记：进入「校验/签名/存档」阶段，供 App 显示「打包中」（与显示文案解耦，不随语言变化）。
            console.log('@@IPA:phase=packaging');
            const signer = new SignatureClient(song, this.user.accountInfo.appleId);
            await signer.sign(this.out);

            console.log(t('file_archived', {out: this.out}));
        } finally {
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
            return await fn();
        } catch (error) {
            const message = error.message || String(error);
            // 用稳定的 error.code 判断商店会话过期（cookie/令牌失效），不依赖文案语言；Apple 英文消息保留兜底。
            const code = error.code;
            const sessionMayBeExpired = this.usedCachedSession
                && (code === 'APPINFO_FAIL' || code === 'LICENSE_FAIL' || code === 'STORE_FAIL'
                    || /401|403|token|session|authenticate|authorization|Sign In to the iTunes Store|iTunes Store|License not found/i.test(message));
            if (!sessionMayBeExpired) throw error;

            console.log(t('relogin'));
            await this.clearSession();
            await this.login({force: true});
            return await fn();
        }
    }
}
