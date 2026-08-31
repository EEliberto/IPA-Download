// Apple StoreServices 登录：使用 Apple bag 下发的 MZFinance 认证端点，并通过 SAP
// 签名（X-Apple-ActionSignature）完成认证。
// 登录协议与安全检查对齐 majd/ipatool 2026-08-29 的上游实现。
//
// 关键对齐点：
//   1. Content-Type: application/x-www-form-urlencoded，但 body 是 plist XML（与 ipatool-sapfix 一致）
//   2. SAP 签名作用于 plist body，写入 X-Apple-ActionSignature header
//   3. 302 redirect：用 attempt=1 的原始 body 重发到 Location URL（不递增 attempt）
//   4. 只信任 bag 下发的 buy.itunes.apple.com 认证端点，并校验 302 重定向
//   5. 对 204/404/5xx 临时响应有限重试；403 不再切换到其他认证端点
//   6. attempt 递增：仅在 attempt==1 且 failureType==-5000 时重试
//
// HTTP 走系统 curl（避免 Node 自带 CA 在 TLS 解密代理下失败）。
import crypto from 'crypto';
import os from 'os';
import path from 'path';
import {execFileSync} from 'child_process';
import {writeFileSync, readFileSync, existsSync, mkdtempSync, rmSync} from 'fs';
import {fileURLToPath} from 'url';
import plist from 'plist';
import {t} from './i18n.js';

// ---- 错误工厂 ----
function ambiguousAuthError() {
    const e = new Error(t('auth_or_2fa'));
    e.code = 'AUTH_OR_2FA';
    return e;
}

function rejectedAuthInputError() {
    const e = new Error(t('auth_input_rejected'));
    e.code = 'AUTH_INPUT_REJECTED';
    return e;
}

// ---- 常量 ----
const CURL = '/usr/bin/curl';
const SCUTIL = '/usr/sbin/scutil';
const STORE_UA = 'Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6';

// 对齐 ipatool-sapfix/pkg/appstore/constants.go
const FAILURE_TYPE_INVALID_CREDENTIALS = '-5000'; // 对应 FailureTypeInvalidCredentials
const CUSTOMER_MESSAGE_BAD_LOGIN       = 'MZFinance.BadLogin.Configurator_message';
const CUSTOMER_MESSAGE_ACCOUNT_DISABLED = 'Your account is disabled.';

// 对齐 ipatool-sapfix/pkg/http/constants.go
const HEADER_SAP_SIGNATURE = 'X-Apple-ActionSignature';

const AUTH_PATH = '/WebObjects/MZFinance.woa/wa/authenticate';
const AUTH_HOST = 'buy.itunes.apple.com';
const MAX_AUTH_REQUEST_ATTEMPTS = 3;
const AUTH_RETRY_DELAY_MS = 250;

// SAP signer 路径
const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_SAP_SIGNER = path.resolve(MODULE_DIR, '..', '..', 'sap-signer');

// ---- 临时目录 ----
let _tmpDir = null;
function tmpDir() {
    if (!_tmpDir) _tmpDir = mkdtempSync(path.join(os.tmpdir(), 'ipa-gsa-'));
    return _tmpDir;
}
export function cleanup() {
    if (_tmpDir) { rmSync(_tmpDir, {recursive: true, force: true}); _tmpDir = null; }
}

// ---- 系统代理 ----
function parseSystemProxySettings() {
    try {
        const out = execFileSync(SCUTIL, ['--proxy'], {timeout: 5000}).toString();
        const value = (key) => (out.match(new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, 'm')) || [])[1]?.trim() || '';
        const exceptionBlock = (out.match(/^\s*ExceptionsList\s*:\s*<array>\s*\{([\s\S]*?)^\s*\}/m) || [])[1] || '';
        const exceptions = [...exceptionBlock.matchAll(/^\s*\d+\s*:\s*(.+)$/gm)].map((match) => match[1].trim());
        return {
            httpEnabled: value('HTTPEnable') === '1',
            httpHost: value('HTTPProxy'),
            httpPort: value('HTTPPort'),
            httpsEnabled: value('HTTPSEnable') === '1',
            httpsHost: value('HTTPSProxy'),
            httpsPort: value('HTTPSPort'),
            socksEnabled: value('SOCKSEnable') === '1',
            socksHost: value('SOCKSProxy'),
            socksPort: value('SOCKSPort'),
            excludeSimpleHostnames: value('ExcludeSimpleHostnames') === '1',
            exceptions,
        };
    } catch { /* ignore */ }
    return {};
}

function proxyFromEnvironment(url) {
    const protocol = new URL(url).protocol;
    if (protocol === 'https:') {
        return process.env.HTTPS_PROXY || process.env.https_proxy
            || process.env.ALL_PROXY || process.env.all_proxy || '';
    }
    return process.env.HTTP_PROXY || process.env.http_proxy
        || process.env.ALL_PROXY || process.env.all_proxy || '';
}

export function proxyBypassListMatches(url, bypassList) {
    const host = new URL(url).hostname.toLowerCase();
    return String(bypassList || '').split(',').some((rawEntry) => {
        let entry = rawEntry.trim().toLowerCase();
        if (!entry) return false;
        if (entry === '*') return true;
        if (entry.includes('://')) {
            try { entry = new URL(entry).hostname.toLowerCase(); }
            catch { return false; }
        } else if ((entry.match(/:/g) || []).length === 1) {
            entry = entry.split(':')[0];
        }
        entry = entry.replace(/^\*\./, '').replace(/^\./, '');
        return host === entry || host.endsWith(`.${entry}`);
    });
}

// curl 不会自动读取 macOS“网络”中的代理设置，因此显式转成 --proxy。
// HTTPS 可经 HTTPS/HTTP CONNECT 代理，也支持常见代理客户端提供的 SOCKS5 端口。
export function systemProxyForURL(url) {
    const host = new URL(url).hostname;
    const noProxy = process.env.NO_PROXY || process.env.no_proxy || '';
    if (proxyBypassListMatches(url, noProxy)) return '';

    const envProxy = proxyFromEnvironment(url);
    if (envProxy) return envProxy;

    const settings = parseSystemProxySettings();
    if ((settings.excludeSimpleHostnames && !host.includes('.'))
        || proxyBypassListMatches(url, (settings.exceptions || []).join(','))) {
        return '';
    }
    const protocol = new URL(url).protocol;
    if (protocol === 'https:' && settings.httpsEnabled && settings.httpsHost && settings.httpsPort) {
        return `http://${settings.httpsHost}:${settings.httpsPort}`;
    }
    if (settings.httpEnabled && settings.httpHost && settings.httpPort) {
        return `http://${settings.httpHost}:${settings.httpPort}`;
    }
    if (settings.socksEnabled && settings.socksHost && settings.socksPort) {
        return `socks5h://${settings.socksHost}:${settings.socksPort}`;
    }
    return '';
}

export const STORE_USER_AGENT = STORE_UA;

// ---- 通用 curl 请求 ----
// jar：cookie 文件路径，传入则读写 cookie（authenticate 与后续下载/购买共享会话）。
export function curlRequest(method, url, {headers = {}, body = null, follow = false, timeout = 30, jar = null} = {}) {
    const dir = tmpDir();
    const outFile = path.join(dir, `out-${crypto.randomBytes(4).toString('hex')}.bin`);
    const hdrFile = path.join(dir, `hdr-${crypto.randomBytes(4).toString('hex')}.txt`);
    const args = ['-sS', '-m', String(timeout), '--connect-timeout', String(Math.min(timeout, 10)), '-X', method, url,
        '-o', outFile, '-D', hdrFile, '-w', '%{http_code}'];
    if (jar) args.push('-b', jar, '-c', jar);
    if (follow) args.push('-L', '--post302');
    const proxy = systemProxyForURL(url);
    if (proxy) args.push('--proxy', proxy);
    for (const [k, v] of Object.entries(headers)) args.push('-H', `${k}: ${v}`);
    if (body !== null) {
        const bodyFile = path.join(dir, `body-${crypto.randomBytes(4).toString('hex')}.bin`);
        writeFileSync(bodyFile, body);
        args.push('--data-binary', `@${bodyFile}`);
    }
    let status = '000';
    let errorDetail = '';
    const execute = (requestArgs) => {
        try {
            errorDetail = '';
            return execFileSync(CURL, requestArgs, {
                maxBuffer: 64 * 1024 * 1024,
                timeout: (timeout + 5) * 1000,
            }).toString().trim();
        } catch (error) {
            errorDetail = Buffer.isBuffer(error?.stderr)
                ? error.stderr.toString('utf8').trim()
                : String(error?.message || error || '').trim();
            return '000';
        }
    };
    status = execute(args);
    // 部分大陆网络存在不可用 IPv6 路由。只有直连完全失败时再强制 IPv4，
    // 不影响正常 IPv6，也不改变用户显式配置的代理线路。
    if (status === '000' && !proxy) status = execute([...args, '--ipv4']);
    const respBody = existsSync(outFile) ? readFileSync(outFile) : Buffer.alloc(0);
    const respHdrs = existsSync(hdrFile) ? readFileSync(hdrFile, 'utf8') : '';
    return {status: Number(status), headers: respHdrs, body: respBody, error: errorDetail};
}

function headerValue(rawHeaders, name) {
    const m = rawHeaders.match(new RegExp(`^${name}:\\s*(.+)$`, 'im'));
    return m ? m[1].trim() : '';
}

// ---- SAP 签名（对齐 mescal.Sign） ----
function sapSignerPath() {
    return process.env.IPA_SAP_SIGNER || DEFAULT_SAP_SIGNER;
}

function signAppleAction(bodyBytes) {
    const signer = sapSignerPath();
    if (!existsSync(signer)) {
        throw new Error(`缺少 Apple SAP 签名组件：${signer}`);
    }
    try {
        const output = execFileSync(signer, [], {
            input: bodyBytes,
            encoding: 'utf8',
            maxBuffer: 1024 * 1024,
            timeout: 35_000,
        }).trim();
        if (!/^[A-Za-z0-9+/]+=*$/.test(output)) {
            throw new Error('签名组件返回了无效数据');
        }
        return Buffer.from(output, 'base64');
    } catch (error) {
        const stderr = Buffer.isBuffer(error?.stderr)
            ? error.stderr.toString('utf8').trim()
            : String(error?.stderr || '').trim();
        const detail = stderr || error.message || String(error);
        throw new Error(`Apple SAP 签名失败：${detail}`);
    }
}

// 对齐 client.go Send() 中的 SignAction 处理
export function buildSignedAuthenticationHeaders(baseHeaders, body, signer = signAppleAction) {
    const bodyBytes = Buffer.isBuffer(body) ? body : Buffer.from(body);
    const signature = signer(bodyBytes);
    if (!Buffer.isBuffer(signature) || signature.length === 0) {
        throw new Error('Apple SAP 签名为空');
    }
    return {...baseHeaders, [HEADER_SAP_SIGNATURE]: signature.toString('base64')};
}

// ---- bag.xml 获取并校验认证端点（对齐上游 Bag()） ----
function extractPlistText(text) {
    const start = text.indexOf('<plist');
    const end = text.indexOf('</plist>');
    if (start >= 0 && end >= start) return text.slice(start, end + '</plist>'.length);
    return text;
}

export function validateAuthenticationEndpoint(endpoint) {
    let parsed;
    try { parsed = new URL(endpoint); }
    catch { throw new Error(`Apple 返回了无效的认证地址：${endpoint || '(empty)'}`); }

    const host = parsed.hostname.toLowerCase();
    const trustedHost = host === AUTH_HOST || host.endsWith(`-${AUTH_HOST}`);
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || !trustedHost || parsed.pathname !== AUTH_PATH) {
        throw new Error(`Apple 返回了不受信任的认证地址：${endpoint}`);
    }
    return parsed.toString();
}

function fetchAuthenticationEndpoint(guid) {
    const url = `https://init.itunes.apple.com/bag.xml?guid=${encodeURIComponent(guid)}`;
    const {status, body} = curlRequest('GET', url, {
        headers: {'User-Agent': STORE_UA, Accept: 'application/xml'},
        follow: true,
        timeout: 20,
    });
    if (status === 0) throw new Error(t('net_failed_suffix'));
    if (status < 200 || status >= 300) throw new Error(`Apple bag 请求失败（HTTP ${status}）`);

    let parsed;
    try { parsed = plist.parse(extractPlistText(body.toString('utf8'))); }
    catch (error) { throw new Error(`Apple bag 返回格式异常：${error.message}`); }
    const authURL = parsed?.urlBag?.authenticateAccount || parsed?.authenticateAccount;
    if (!authURL) throw new Error('Apple bag 缺少认证地址');
    return validateAuthenticationEndpoint(authURL);
}

// ---- 构建登录请求参数（对齐 loginRequest().Payload.Content） ----
// 注意：plist.build() 序列化为 XML plist，但 Content-Type 为 application/x-www-form-urlencoded
// 这是 ipatool-sapfix 的 XMLPayload 行为（参见 payload.go）。
export function buildLoginBody(email, password, code, guid, attempt) {
    return plist.build({
        appleId: email,
        attempt: String(attempt),
        guid,
        password: `${password}${String(code || '').replace(/\s+/g, '')}`,
        rmp: '0',
        why: 'signIn',
    });
}

// ---- 发送单次带 SAP 签名的 POST（不自动跟随 redirect） ----
// 对齐 client.go NewClient() 中的 CheckRedirect: ErrUseLastResponse（auth URL 不自动跟随）
function postWithSAP(url, body, jar) {
    const baseHeaders = {
        'User-Agent': STORE_UA,
        // 对齐 loginRequest() Headers: {"Content-Type": "application/x-www-form-urlencoded"}
        // body 是 plist XML，但 Content-Type 是 form-urlencoded（ipatool-sapfix 的准确行为）
        'Content-Type': 'application/x-www-form-urlencoded',
    };
    const headers = buildSignedAuthenticationHeaders(baseHeaders, body);
    return curlRequest('POST', url, {headers, body, follow: false, timeout: 30, jar});
}

export function isRetryableAuthenticationStatus(status) {
    const value = Number(status);
    return value === 204 || value === 404 || (value >= 500 && value <= 599);
}

function sleepSync(milliseconds) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

// 对齐上游 sendAuthenticationRequest：临时 HTTP 响应最多重发三次，403 不重试。
export function sendAuthenticationRequest(url, body, jar, send = postWithSAP, sleep = sleepSync) {
    const statuses = [];
    let res;
    for (let attempt = 1; attempt <= MAX_AUTH_REQUEST_ATTEMPTS; attempt++) {
        res = send(url, body, jar);
        if (!isRetryableAuthenticationStatus(res.status)) return res;
        statuses.push(res.status);
        if (attempt < MAX_AUTH_REQUEST_ATTEMPTS) sleep(attempt * AUTH_RETRY_DELAY_MS);
    }
    throw new Error(`Apple 认证请求重试 ${MAX_AUTH_REQUEST_ATTEMPTS} 次后仍失败（HTTP ${statuses.join(', ')}）`);
}

// ---- 核心登录循环（精确对齐 login() for 循环）----
//
// ipatool-sapfix 逻辑：
//   for attempt := 1; retry && attempt <= 4; attempt++ {
//       requestAttempt = attempt
//       if redirect != "" { requestAttempt = 1 }  // redirect 时不递增 attempt
//       request = loginRequest(email, pwd, code, guid, endpoint, requestAttempt)
//       request.URL = redirect || request.URL    // redirect 时用 redirect URL，清空 redirect
//       parseLoginResponse(&res, attempt, authCode) -> (retry, redirect, err)
//   }
//
function storePasswordAuthenticate(email, password, code, guid, jar, endpoint) {
    let redirect = '';
    let retry = true;
    let res = null;

    for (let attempt = 1; retry && attempt <= 4; attempt++) {
        // 对齐：redirect 时 requestAttempt 保持 1，用原 body 重发
        const requestAttempt = redirect !== '' ? 1 : attempt;
        const body = buildLoginBody(email, password, code, guid, requestAttempt);

        const targetURL = redirect !== '' ? redirect : endpoint;
        redirect = ''; // 清空，对齐：request.URL, _ = util.IfEmpty(redirect, request.URL), ""

        res = sendAuthenticationRequest(targetURL, body, jar);

        // parseLoginResponse 逻辑
        const parsed = parseLoginResponse(res, attempt, code);
        retry = parsed.retry;
        redirect = parsed.redirect;
        if (parsed.error) throw parsed.error;
        if (!retry) {
            // 登录成功，返回解析出的数据
            return {res, parsed: parsed.data};
        }
    }

    if (retry) {
        // too many attempts
        throw new Error(t('store_token_failed'));
    }

    throw new Error(t('store_token_failed'));
}

// 对齐 parseLoginResponse()
export function parseLoginResponse(res, attempt, authCode) {
    const status = res.status;

    // 302 redirect：返回 Location，重发
    if (status === 302) {
        const location = headerValue(res.headers, 'location');
        if (location) {
            try {
                return {retry: true, redirect: validateAuthenticationEndpoint(location), error: null, data: null};
            } catch (error) {
                return {retry: false, redirect: '', error, data: null};
            }
        }
        return {retry: false, redirect: '', error: new Error('Apple 认证重定向缺少地址'), data: null};
    }

    // 非重定向但也不是成功响应，尝试解析 plist
    let parsed = null;
    if (res.body && res.body.length > 0) {
        try { parsed = parsePlistLoose(res.body, t('ctx_store_login_resp')); } catch { /* ignore */ }
    }

    if (!parsed) {
        if (status === 0) {
            return {retry: false, redirect: '', error: new Error(t('net_failed_suffix')), data: null};
        }
        if (status === 403) {
            return {retry: false, redirect: '', error: new Error(t('sap_auth_rejected')), data: null};
        }
        if (status !== 200) {
            return {retry: false, redirect: '', error: new Error(t('auth_http_failed', {status})), data: null};
        }
        // 无法解析 plist，视为服务端错误
        return {retry: false, redirect: '', error: new Error(t('store_token_failed')), data: null};
    }

    const failureType = String(parsed.failureType || '');
    const customerMessage = String(parsed.customerMessage || '');

    // attempt==1 且 failureType==-5000（FailureTypeInvalidCredentials）→ 重试
    if (attempt === 1 && failureType === FAILURE_TYPE_INVALID_CREDENTIALS) {
        return {retry: true, redirect: '', error: null, data: null};
    }

    // Apple 对错误密码和 2FA 挑战都会返回同一个 Configurator_message，
    // 不能在这里武断地将它归类为 2FA。
    if (failureType === '' && customerMessage === CUSTOMER_MESSAGE_BAD_LOGIN) {
        return {
            retry: false,
            redirect: '',
            error: authCode ? rejectedAuthInputError() : ambiguousAuthError(),
            data: null,
        };
    }

    // failureType=="" && customerMessage=="Your account is disabled."
    if (failureType === '' && customerMessage === CUSTOMER_MESSAGE_ACCOUNT_DISABLED) {
        return {retry: false, redirect: '', error: new Error(t('account_disabled')), data: null};
    }

    // failureType != "" → 错误
    if (failureType !== '') {
        const msg = customerMessage || t('store_token_failed');
        return {retry: false, redirect: '', error: new Error(msg), data: null};
    }

    // 成功条件：有 passwordToken 和 dsPersonId
    if (status !== 200 || !parsed.passwordToken || !parsed.dsPersonId) {
        return {retry: false, redirect: '', error: new Error(t('store_token_failed')), data: null};
    }

    return {retry: false, redirect: '', error: null, data: parsed};
}

// ---- plist 解析（宽松）----
export function parsePlistLoose(buf, context = t('ctx_apple_resp')) {
    let xml = buf.toString('utf8').trim();
    if (!xml) throw new Error(t('empty_resp', {context}));
    if (!/^<\?xml/i.test(xml) && !/^<plist/i.test(xml)) {
        xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0">${xml}</plist>`;
    }
    return plist.parse(xml);
}

// ---- 对外暴露的登录入口（对齐 Login() → login()） ----
export async function storeLogin(email, password, code, guid, cookieText = '', pod = '') {
    const jar = path.join(tmpDir(), `store-cookies-${crypto.createHash('sha256').update(String(email || '')).digest('hex').slice(0, 12)}.txt`);
    if (cookieText) writeFileSync(jar, cookieText);

    // 上游已删除 native/fast 与 legacy fallback，只使用 bag 下发并校验过的认证地址。
    const authEndpoint = fetchAuthenticationEndpoint(guid);
    const {res, parsed} = storePasswordAuthenticate(email, password, code, guid, jar, authEndpoint);

    // 构建用户信息（对齐 login() 返回 Account）
    const storeFront = headerValue(res.headers, 'x-set-apple-store-front');
    const newPod = headerValue(res.headers, 'pod') || (res.headers.match(/Pod=(\d+)/) || [])[1] || '';
    const dsid = parsed.dsPersonId;

    const authHeaders = {
        'X-Dsid': dsid,
        'iCloud-DSID': dsid,
        'X-Token': parsed.passwordToken,
    };
    if (storeFront) authHeaders['X-Apple-Store-Front'] = storeFront;

    const cookieOut = existsSync(jar) ? readFileSync(jar, 'utf8') : '';

    return {
        accountInfo: parsed.accountInfo || {appleId: email, address: {firstName: '', lastName: ''}},
        dsPersonId: dsid,
        passwordToken: parsed.passwordToken,
        pod: newPod || pod || '',
        authHeaders,
        cookieText: cookieOut,
    };
}

// ---- Cookie jar 工具 ----
// 把缓存的 cookie 文本写回一个临时 jar 文件，返回路径（供复用会话时使用）。
export function restoreCookieJar(cookieText, seed = 'default') {
    if (!cookieText) return null;
    const digest = crypto.createHash('sha256').update(String(seed || 'default')).digest('hex').slice(0, 12);
    const jar = path.join(tmpDir(), `store-cookies-${digest}.txt`);
    writeFileSync(jar, cookieText);
    return jar;
}

export function readCookieJar(jar) {
    return jar && existsSync(jar) ? readFileSync(jar, 'utf8') : '';
}
