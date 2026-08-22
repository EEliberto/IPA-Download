// Apple GrandSlam (GSA) 登录：SRP-6a + Anisette + 2FA，最终换取 StoreServices 令牌。
// Apple 已停用旧的明文密码登录，此模块对齐 SideStore/apple-private-apis 的可用流程。
//
// HTTP 一律走系统 curl：
//   - gsa.apple.com 在部分网络环境（如开启 TLS 解密的代理）下会被 MITM，Node 自带 CA 校验会失败；
//     curl 配合系统代理(CONNECT 隧道)能拿到真实 Apple 证书。
//   - 自动读取 macOS 系统代理(scutil --proxy)并传给 curl。
import crypto from 'crypto';
import os from 'os';
import path from 'path';
import {execFileSync} from 'child_process';
import {writeFileSync, readFileSync, existsSync, mkdtempSync, rmSync} from 'fs';
import plist from 'plist';
import {t} from './i18n.js';

function needs2faError() {
    const e = new Error(t('needs_2fa'));
    e.code = 'NEEDS_2FA';
    return e;
}

const CURL = '/usr/bin/curl';
const SCUTIL = '/usr/sbin/scutil';
const GSA_ENDPOINT = 'https://gsa.apple.com/grandslam/GsService2';
const DEFAULT_NATIVE_AUTH_URL = 'https://auth.itunes.apple.com/auth/v1/native/fast';
// 多个公共 anisette 服务器做兜底（取自 SideStore 官方推荐列表）；单个挂了就换下一个。
// 可用 ANISETTE_SERVER 环境变量在最前面插入自定义服务器。
const ANISETTE_SERVERS = [
    ...(process.env.ANISETTE_SERVER ? [process.env.ANISETTE_SERVER] : []),
    'https://ani.sidestore.io',
    'https://ani.f1sh.me',
    'https://ani.npeg.us',
    'https://ani.sidestore.app',
    'https://ani.846969.xyz',
    'https://anisette.wedotstud.io',
    'https://ani.neoarz.com',
    'https://ani3server.fly.dev',
    'https://ani.jaydenha.uk',
    'https://anisette.crystall1ne.dev',
    'https://sideloadly.io/anisette/irGb3Quww8zrhgqnzmrx',
];
const GSA_UA = 'akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0';
const STORE_UA = 'Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6';

// ---- SRP (RFC5054 2048-bit, SHA-256), 对齐 srp v0.6.0 ----
const N = BigInt('0x' + 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73');
const g = 2n;
const modpow = (b, e, m) => { let r = 1n; b %= m; if (b < 0n) b += m; while (e > 0n) { if (e & 1n) r = r * b % m; e >>= 1n; b = b * b % m; } return r; };
const toBuf = (x) => { let h = x.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex'); };
const toBI = (buf) => (buf.length ? BigInt('0x' + buf.toString('hex')) : 0n);
const padL = (buf, len) => Buffer.concat([Buffer.alloc(len - buf.length), buf]);
const sha256 = (...parts) => { const h = crypto.createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };

let _tmpDir = null;
function tmpDir() {
    if (!_tmpDir) _tmpDir = mkdtempSync(path.join(os.tmpdir(), 'ipa-gsa-'));
    return _tmpDir;
}
export function cleanup() {
    if (_tmpDir) { rmSync(_tmpDir, {recursive: true, force: true}); _tmpDir = null; }
}

function systemProxy() {
    if (process.env.IPA_BYPASS_SYSTEM_PROXY === '1') return '';
    try {
        const out = execFileSync(SCUTIL, ['--proxy'], {timeout: 5000}).toString();
        const httpsOn = /HTTPSEnable\s*:\s*1/.test(out);
        const host = (out.match(/HTTPSProxy\s*:\s*(\S+)/) || [])[1];
        const port = (out.match(/HTTPSPort\s*:\s*(\d+)/) || [])[1];
        if (httpsOn && host && port) return `http://${host}:${port}`;
    } catch { /* ignore */ }
    return process.env.HTTPS_PROXY || process.env.https_proxy || '';
}

export const STORE_USER_AGENT = STORE_UA;

// 通用 curl 请求；headers 为 {k:v}，返回 {status, headers, body}
// jar：cookie 文件路径，传入则读写 cookie（authenticate 与后续下载/购买共享会话）。
export function curlRequest(method, url, {headers = {}, body = null, follow = false, timeout = 30, jar = null, http2 = false} = {}) {
    const dir = tmpDir();
    const outFile = path.join(dir, `out-${crypto.randomBytes(4).toString('hex')}.bin`);
    const hdrFile = path.join(dir, 'hdr.txt');
    // Apple 的旧式 StoreServices plist 接口在 HTTP/2 下偶尔返回 403 且 body 为空。
    // AssppWeb 当前实现同样固定使用 HTTP/1.1。
    const args = ['-s', http2 ? '--http2' : '--http1.1', '-m', String(timeout), '-X', method, url,
        '-o', outFile, '-D', hdrFile, '-w', '%{http_code}'];
    if (jar) args.push('-b', jar, '-c', jar);
    if (follow) args.push('-L', '--post302');
    let isAppleEndpoint = false;
    try {
        const hostname = new URL(url).hostname.toLowerCase();
        isAppleEndpoint = hostname === 'apple.com' || hostname.endsWith('.apple.com');
    } catch { /* keep normal proxy behavior for malformed/non-URL input */ }
    // Local proxy applications can keep HTTPS_PROXY injected even after the
    // user switches networks. Apple's commerce edge rejects those tunneled
    // requests intermittently (empty 301/403/503), while direct GSA/PDP/Store
    // requests succeed. Allow an explicit opt-in for environments that truly
    // require an Apple proxy.
    const bypassProxy = process.env.IPA_BYPASS_SYSTEM_PROXY === '1'
        || (isAppleEndpoint && process.env.IPA_ALLOW_APPLE_PROXY !== '1');
    if (bypassProxy) {
        args.push('--noproxy', '*');
    } else {
        const proxy = systemProxy();
        if (proxy) args.push('--proxy', proxy);
    }
    for (const [k, rawValue] of Object.entries(headers)) {
        const values = Array.isArray(rawValue) ? rawValue : [rawValue];
        for (const value of values) args.push('-H', `${k}: ${value}`);
    }
    if (body !== null) {
        const bodyFile = path.join(dir, 'body.bin');
        writeFileSync(bodyFile, body);
        args.push('--data-binary', `@${bodyFile}`);
    }
    let status = '000';
    try { status = execFileSync(CURL, args, {maxBuffer: 64 * 1024 * 1024, timeout: (timeout + 5) * 1000}).toString().trim(); }
    catch { status = '000'; }
    const respBody = existsSync(outFile) ? readFileSync(outFile) : Buffer.alloc(0);
    const respHdrs = existsSync(hdrFile) ? readFileSync(hdrFile, 'utf8') : '';
    return {status: Number(status), headers: respHdrs, body: respBody};
}

function headerValue(rawHeaders, name) {
    // curl may append several header blocks (proxy CONNECT / redirects). The
    // final matching value belongs to the response returned to the caller.
    const matches = [...rawHeaders.matchAll(new RegExp(`^${name}:\\s*(.+)$`, 'gim'))];
    return matches.length ? matches.at(-1)[1].trim() : '';
}

function podPrefix(pod) {
    return pod ? `p${pod}-` : '';
}

function storeAuthURL(guid, pod = '') {
    return `https://${podPrefix(pod)}buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate?guid=${encodeURIComponent(guid)}`;
}

const LEGACY_STORE_AUTH_URL = 'https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate';

function storeAuthCandidates(guid) {
    const dynamic = nativeAuthURL(fetchNativeAuthEndpoint(guid), guid);
    const native = nativeAuthURL(DEFAULT_NATIVE_AUTH_URL, guid);
    // Apple changes which endpoint accepts authentication by edge/account. The
    // bag can temporarily advertise legacy MZFinance even while /native/fast/
    // remains the working endpoint, so keep both explicit candidates.
    return [...new Set([native, dynamic, LEGACY_STORE_AUTH_URL, storeAuthURL(guid)])];
}

function postStoreAuth(url, headers, body, jar) {
    let endpoint = url;
    let res = null;
    // A Store pod is assigned with 301/302. Re-POST the exact plist body;
    // automatic redirect handling may otherwise convert the request to GET.
    for (let redirectCount = 0; redirectCount < 4; redirectCount++) {
        res = curlRequest('POST', endpoint, {headers, body, follow: false, timeout: 30, jar});
        if (res.status < 300 || res.status >= 400) return res;
        const location = headerValue(res.headers, 'location');
        if (!location) return res;
        endpoint = new URL(location, endpoint).toString();
    }
    return res;
}

function storeAuthRejected(res) {
    const status = res?.status || 0;
    const e = new Error(t('store_http_rejected', {status}));
    e.code = 'STORE_HTTP_REJECTED';
    return e;
}

function shouldFallbackStoreAuth(res) {
    const status = Number(res?.status || 0);
    const text = res?.body?.toString('utf8').trimStart().toLowerCase() || '';
    return !res?.body?.length
        || status < 200
        || status >= 300
        || text.startsWith('<!doctype html')
        || text.startsWith('<html')
        || [204, 403, 404, 503].includes(status);
}

function nativeAuthURL(endpoint, guid) {
    const url = new URL(endpoint);
    url.searchParams.set('guid', guid);
    return url.toString();
}

function normalizeAuthEndpoint(raw) {
    try {
        const url = new URL(raw);
        if (url.hostname === 'auth.itunes.apple.com') {
            let pathname = url.pathname.replace(/\/+$/, '');
            if (!pathname.endsWith('/fast')) pathname += '/fast';
            // As of August 2026 Apple's native auth edge accepts /fast and
            // rejects /fast/ with 301/403. Keep the canonical path slashless.
            url.pathname = pathname;
        }
        return url.toString();
    } catch {
        return DEFAULT_NATIVE_AUTH_URL;
    }
}

function extractPlistText(text) {
    const start = text.indexOf('<plist');
    const end = text.indexOf('</plist>');
    if (start >= 0 && end >= start) return text.slice(start, end + '</plist>'.length);
    return text;
}

function fetchNativeAuthEndpoint(guid) {
    try {
        const url = new URL('https://init.itunes.apple.com/bag.xml');
        url.searchParams.set('guid', guid);
        const {status, body} = curlRequest('GET', url.toString(), {
            headers: {'User-Agent': STORE_UA, Accept: 'application/xml'},
            follow: true,
            timeout: 20,
        });
        if (status < 200 || status >= 300) return DEFAULT_NATIVE_AUTH_URL;
        const parsed = plist.parse(extractPlistText(body.toString('utf8')));
        const urlBag = parsed?.urlBag || {};
        const authURL = parsed?.authenticateAccount || urlBag.authenticateAccount;
        return authURL ? normalizeAuthEndpoint(authURL) : DEFAULT_NATIVE_AUTH_URL;
    } catch {
        return DEFAULT_NATIVE_AUTH_URL;
    }
}

function podFromHeaders(rawHeaders) {
    return headerValue(rawHeaders, 'pod') || (rawHeaders.match(/Pod=(\d+)/) || [])[1] || '';
}

export function parsePlistLoose(buf, context = t('ctx_apple_resp')) {
    let xml = buf.toString('utf8').trim();
    if (!xml) throw new Error(t('empty_resp', {context}));
    if (!/^<\?xml/i.test(xml) && !/^<plist/i.test(xml)) {
        xml = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0">${xml}</plist>`;
    }
    return plist.parse(xml);
}

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

function debugAuthenticationShape(spd, status) {
    if (process.env.IPA_DEBUG_AUTH !== '1') return;
    const safeParameters = {};
    const visit = (value, path = '') => {
        if (!value || typeof value !== 'object' || Buffer.isBuffer(value)) return;
        for (const [key, child] of Object.entries(value)) {
            const childPath = path ? `${path}.${key}` : key;
            if (/pdp|srp|password.?version|iteration|salt|protocol/i.test(key)
                && ['string', 'number', 'boolean'].includes(typeof child)) {
                safeParameters[childPath] = child;
            } else if (child && typeof child === 'object') {
                visit(child, childPath);
            }
        }
    };
    visit(spd);
    console.error(`[auth:shape] spdKeys=${Object.keys(spd || {}).sort().join(',')} statusKeys=${Object.keys(status || {}).sort().join(',')} tokenIDs=${Object.keys(spd?.t || {}).sort().join(',')} parameters=${JSON.stringify(safeParameters)}`);
}

// 取 anisette 设备标识：遍历所有服务器，全部失败再整体重试一遍（公共服务器经常临时 5xx）。
async function fetchAnisette() {
    let lastErr = null;
    for (let pass = 0; pass < 6; pass++) {
        for (const server of ANISETTE_SERVERS) {
            try {
                const {status, body} = curlRequest('GET', server, {timeout: 12});
                if (status !== 200) { lastErr = new Error(`anisette ${server} HTTP ${status}`); continue; }
                const ani = JSON.parse(body.toString('utf8'));
                if (ani['X-Apple-I-MD'] && ani['X-Apple-I-MD-M']) return ani;
                lastErr = new Error(t('anisette_missing_fields', {server}));
            } catch (e) { lastErr = e; }
        }
        if (pass === 0) await sleep(700);
    }
    throw new Error(t('anisette_failed', {msg: lastErr ? lastErr.message : t('unknown_error')}));
}

function cpdFromAnisette(ani) {
    return {
        'X-Apple-I-Client-Time': ani['X-Apple-I-Client-Time'],
        'X-Apple-I-MD': ani['X-Apple-I-MD'],
        'X-Apple-I-MD-LU': ani['X-Apple-I-MD-LU'],
        'X-Apple-I-MD-M': ani['X-Apple-I-MD-M'],
        'X-Apple-I-MD-RINFO': ani['X-Apple-I-MD-RINFO'],
        'X-Apple-I-SRL-NO': ani['X-Apple-I-SRL-NO'],
        'X-Apple-I-TimeZone': ani['X-Apple-I-TimeZone'],
        'X-Apple-Locale': ani['X-Apple-Locale'],
        'X-Mme-Device-Id': ani['X-Mme-Device-Id'],
        bootstrap: true,
        capp: 'itunesstored',
        ckgen: true,
        icscrec: true,
        loc: 'en_GB',
        papp: 'com.apple.AppStore',
        pbe: false,
        prkgen: true,
        svct: 'iTunes',
    };
}

function gsaPost(bodyObj, ani) {
    const body = plist.build(bodyObj);
    const headers = {
        'Content-Type': 'text/x-xml-plist',
        'Accept': '*/*',
        'User-Agent': GSA_UA,
        'X-MMe-Client-Info': ani['X-MMe-Client-Info'],
    };
    // 瞬时错误（网络失败 / 5xx / 限流）重试几次，避免一次抖动就让整个登录失败。
    let lastStatus = 0;
    for (let attempt = 0; attempt < 3; attempt++) {
        const {status, body: respBody} = curlRequest('POST', GSA_ENDPOINT, {headers, body, timeout: 30});
        if (process.env.IPA_DEBUG_AUTH === '1') {
            const firstTag = (respBody.toString('utf8').match(/<([A-Za-z][A-Za-z0-9:-]*)\b/) || [])[1] || '';
            console.error(`[auth:gsa] operation=${bodyObj?.Request?.o || 'unknown'} status=${status} bytes=${respBody.length} firstTag=${firstTag}`);
        }
        if (status === 200) {
            const parsed = parsePlistLoose(respBody, t('ctx_gsa_resp'));
            return parsed.Response || parsed;
        }
        lastStatus = status;
        if (![0, 429, 500, 502, 503, 504].includes(status)) break;
    }
    throw new Error(t('gsa_http', {status: lastStatus}));
}

// 完整 SRP 握手，返回解密后的 spd（含 adsid / GsIdmsToken / t.tokens）与 Status。
function srpLogin(email, password, ani) {
    const cpd = cpdFromAnisette(ani);
    const a = BigInt('0x' + crypto.randomBytes(32).toString('hex'));
    const Abuf = toBuf(modpow(g, a, N));

    const initR = gsaPost({Header: {Version: '1.0.1'}, Request: {A2k: Abuf, cpd, o: 'init', ps: ['s2k', 's2k_fo'], u: email}}, ani);
    if (initR.Status?.ec !== 0 || !initR.s) {
        throw new Error(initR.Status?.em || t('gsa_init_failed'));
    }
    const salt = initR.s, Bbuf = initR.B, iters = Number(initR.i), cCookie = initR.c;
    const Bbi = toBI(Bbuf), Btrim = toBuf(Bbi);

    // s2k：x = H(salt | H("" | ":" | PBKDF2(SHA256(pw), salt, iters)))
    const pwBuf = crypto.pbkdf2Sync(sha256(Buffer.from(password, 'utf8')), salt, iters, 32, 'sha256');
    const x = toBI(sha256(salt, sha256(Buffer.from(':'), pwBuf)));
    const k = toBI(sha256(padL(toBuf(N), 256), padL(toBuf(g), 256)));
    const u = toBI(sha256(Abuf, Btrim));
    let base = (Bbi - (k * modpow(g, x, N)) % N) % N; if (base < 0n) base += N;
    const S = toBuf(modpow(base, a + u * x, N));
    const K = sha256(S);

    const nHash = sha256(padL(toBuf(N), 256));
    const gHash = sha256(padL(toBuf(g), 256));
    const xored = Buffer.alloc(32); for (let i = 0; i < 32; i++) xored[i] = gHash[i] ^ nHash[i];
    const M1 = sha256(xored, sha256(Buffer.from(email, 'utf8')), salt, Abuf, Btrim, K);

    const compR = gsaPost({Header: {Version: '1.0.1'}, Request: {M1, c: cCookie, cpd, o: 'complete', u: email}}, ani);
    if (compR.Status?.ec !== 0) {
        // ec -22406 等：密码错误
        throw new Error(compR.Status?.em || t('wrong_password'));
    }
    if (!compR.M2 || Buffer.compare(compR.M2, sha256(Abuf, M1, K)) !== 0) {
        throw new Error(t('gsa_m2_mismatch'));
    }
    const edKey = crypto.createHmac('sha256', K).update('extra data key:').digest();
    const edIv = crypto.createHmac('sha256', K).update('extra data iv:').digest().subarray(0, 16);
    const dec = crypto.createDecipheriv('aes-256-cbc', edKey, edIv);
    const pt = Buffer.concat([dec.update(compR.spd), dec.final()]);
    const spd = parsePlistLoose(pt, 'spd');
    return {spd, status: compR.Status};
}

function build2faHeaders(ani, adsid, gsToken) {
    const idToken = Buffer.from(`${adsid}:${gsToken}`).toString('base64');
    return {
        'X-Apple-I-Client-Time': ani['X-Apple-I-Client-Time'],
        'X-Apple-I-MD': ani['X-Apple-I-MD'],
        'X-Apple-I-MD-LU': ani['X-Apple-I-MD-LU'],
        'X-Apple-I-MD-M': ani['X-Apple-I-MD-M'],
        'X-Apple-I-MD-RINFO': ani['X-Apple-I-MD-RINFO'],
        'X-Apple-I-SRL-NO': ani['X-Apple-I-SRL-NO'],
        'X-Apple-I-TimeZone': ani['X-Apple-I-TimeZone'],
        'X-Apple-Locale': ani['X-Apple-Locale'],
        'X-Mme-Device-Id': ani['X-Mme-Device-Id'],
        'X-Mme-Client-Info': ani['X-MMe-Client-Info'],
        'X-Apple-App-Info': 'com.apple.gs.xcode.auth',
        'X-Xcode-Version': '11.2 (11B41)',
        'Content-Type': 'text/x-xml-plist',
        'Accept': 'text/x-xml-plist',
        'User-Agent': 'Xcode',
        'Accept-Language': 'en-us',
        'X-Apple-Identity-Token': idToken,
        'Loc': ani['X-Apple-Locale'],
    };
}

function encodedAccountToken(adsid, token) {
    return Buffer.from(`${adsid}:${token}`).toString('base64');
}

function performPDPIntermission(password, ani, spd) {
    const adsid = String(spd?.adsid || '');
    const dsid = String(spd?.DsPrsId || '');
    const gsToken = String(spd?.GsIdmsToken || '');
    if (!adsid || !gsToken) return {attempted: false, status: 0};

    const serviceToken = spd?.t?.['com.apple.gs.appleid.auth']?.token;
    const heartbeat = spd?.t?.['com.apple.gs.idms.hb']?.token;
    const pet = spd?.t?.['com.apple.gs.idms.pet']?.token;
    if (!serviceToken) return {attempted: false, status: 0};
    const commonHeaders = {
        ...build2faHeaders(ani, adsid, gsToken),
        'User-Agent': 'akd/1.0 CFNetwork/3860.700.1 Darwin/25.6.0',
        'X-Mme-Client-Info': '<Mac16,3> <macOS;26.6.2;25G83> <com.apple.AuthKit/1 (com.apple.akd/1)>',
        'Content-Type': 'application/json',
        Accept: 'application/json',
        // AuthKit signs GS tokens with the alternate DSID, but the identity-id
        // header is the numeric Store/DS person id. Supplying the alternate
        // DSID in both places makes PDP reject an otherwise valid token (401).
        ...(dsid ? {'X-Apple-I-Identity-Id': dsid, 'X-Apple-DSID': dsid} : {}),
        'X-Apple-I-Locale': ani['X-Apple-Locale'],
        ...(heartbeat ? {'X-Apple-HB-Token': encodedAccountToken(adsid, heartbeat)} : {}),
        ...(pet ? {'X-Apple-PE-Token': encodedAccountToken(adsid, pet)} : {}),
        // AKGrandSlamRequestProvider adds this whenever the authenticated
        // account carries a continuation token. Omitting it causes PDP -9001.
        'X-Apple-I-CK-Presence': Boolean(spd?.c || spd?.ck) ? 'true' : 'false',
    };
    // Apple's current PDP edge uses X-Apple-I-GS-Token. The older
    // X-Apple-GS-Token spelling is still present in local AuthKit binaries but
    // is treated by the server as if no token was sent (PDP -9001).
    delete commonHeaders['X-Apple-Identity-Token'];
    const body = Buffer.from(JSON.stringify({password}), 'utf8');
    const response = curlRequest('POST', 'https://gsa.apple.com/grandslam/ws/pdp/intermission', {
        headers: {
            ...commonHeaders,
            'X-Apple-I-GS-Token': encodedAccountToken(adsid, serviceToken),
        },
        body,
        timeout: 30,
        http2: true,
    });
    if (process.env.IPA_DEBUG_AUTH === '1') {
        console.error(`[auth:pdp] status=${response.status} bytes=${response.body.length}`);
    }
    return {attempted: true, status: response.status, body: response.body};
}

function send2faPush(ani, adsid, gsToken) {
    for (let attempt = 0; attempt < 3; attempt++) {
        const {status} = curlRequest('GET', 'https://gsa.apple.com/auth/verify/trusteddevice',
            {headers: build2faHeaders(ani, adsid, gsToken), timeout: 25});
        if (status >= 200 && status < 300) return true;
        if (![0, 429, 500, 502, 503, 504].includes(status)) break;
    }
    return false;
}

function validate2fa(ani, adsid, gsToken, code) {
    const headers = {...build2faHeaders(ani, adsid, gsToken), 'security-code': code};
    for (let attempt = 0; attempt < 3; attempt++) {
        const {status, body} = curlRequest('GET', 'https://gsa.apple.com/grandslam/GsService2/validate',
            {headers, timeout: 25});
        if (process.env.IPA_DEBUG_AUTH === '1') {
            const firstTag = (body.toString('utf8').match(/<([A-Za-z][A-Za-z0-9:-]*)\b/) || [])[1] || '';
            console.error(`[auth:2fa] status=${status} bytes=${body.length} firstTag=${firstTag}`);
        }
        let vr = null; try { vr = plist.parse(body.toString('utf8')); } catch { /* ignore */ }
        const ec = vr?.Status?.ec ?? vr?.ec;
        if (ec === 0) return true;
        // 明确返回了错误码（如验证码错误）就不重试；只有瞬时网络/5xx 才重试。
        if (typeof ec === 'number') return false;
        if (![0, 429, 500, 502, 503, 504].includes(status)) return false;
    }
    return false;
}

// 用 PET 当密码调 MZFinance authenticate，跟随 302 pod 跳转，拿 StoreServices 令牌。
// jar：cookie 文件，authenticate 会在此种下会话 cookie，供后续下载/购买请求复用。
function storeAuthenticate(email, pet, ani, adsid, gsToken, guid, jar) {
    const idToken = Buffer.from(`${adsid}:${gsToken}`).toString('base64');
    const body = plist.build({appleId: email, attempt: '1', createSession: 'true', guid, password: pet, rmp: '0', why: 'signIn'});
    const headers = {
        'User-Agent': STORE_UA,
        // Match ipatool v2.3.2 exactly. ApplePackage uses x-apple-plist, but
        // ipatool's verified legacy fallback uses this content type.
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Apple-I-MD': ani['X-Apple-I-MD'],
        'X-Apple-I-MD-M': ani['X-Apple-I-MD-M'],
        'X-Apple-I-MD-RINFO': ani['X-Apple-I-MD-RINFO'],
        'X-Apple-I-MD-LU': ani['X-Apple-I-MD-LU'],
        'X-Mme-Device-Id': ani['X-Mme-Device-Id'],
        'X-Apple-I-Client-Time': ani['X-Apple-I-Client-Time'],
        'X-Apple-I-TimeZone': ani['X-Apple-I-TimeZone'],
        'X-Apple-Identity-Token': idToken,
    };
    let res = null;
    for (let pass = 0; pass < 2; pass++) {
        for (const endpoint of storeAuthCandidates(guid)) {
            res = postStoreAuth(endpoint, headers, body, jar);
            if (process.env.IPA_DEBUG_AUTH === '1') {
                const contentType = headerValue(res?.headers || '', 'content-type');
                const location = headerValue(res?.headers || '', 'location');
                const firstTag = (res?.body?.toString('utf8').match(/<([A-Za-z][A-Za-z0-9:-]*)\b/) || [])[1] || '';
                console.error(`[auth:store] endpoint=${new URL(endpoint).origin}${new URL(endpoint).pathname} status=${res?.status || 0} bytes=${res?.body?.length || 0} contentType=${contentType} firstTag=${firstTag} redirected=${location ? 'yes' : 'no'}`);
            }
            if (!shouldFallbackStoreAuth(res)) break;
        }
        if (!shouldFallbackStoreAuth(res)) break;
    }
    if (shouldFallbackStoreAuth(res)) {
        throw storeAuthRejected(res);
    }
    const parsed = parsePlistLoose(res.body, t('ctx_store_login_resp'));
    if (parsed.customerMessage === 'MZFinance.BadLogin.Configurator_message' && !parsed.passwordToken) {
        throw needs2faError();
    }
    if (!parsed.passwordToken || !parsed.dsPersonId) {
        throw new Error(parsed.customerMessage || t('store_token_failed'));
    }
    const storeFront = headerValue(res.headers, 'x-set-apple-store-front');
    const podFromUrl = (res.headers.match(/Pod=(\d+)/) || [])[1] || '';
    return {parsed, storeFront, pod: podFromUrl};
}

// Asspp / ApplePackage 风格的 StoreServices 登录：稳定 guid + 账号密码 + 既有 cookies。
// 首次登录需要 2FA；之后复用 cookies 轮换 passwordToken，避免重新创建 GSA/anisette 设备。
function storePasswordAuthenticate(email, password, code, guid, jar) {
    const headers = {
        'User-Agent': STORE_UA,
        'Content-Type': 'application/x-apple-plist',
    };

    let res = null;
    const endpoints = storeAuthCandidates(guid);
    // Configurator's `attempt` is a flow selector, not an incrementing retry
    // counter. Apple currently expects 4 for the password-only challenge and
    // 2 when the six-digit trusted-device code is appended to the password.
    // Sending 1 here makes /native/fast/ reject an otherwise valid login with
    // an empty 403, which was previously misreported as a network problem.
    const flowAttempt = code ? '2' : '4';
    for (let networkAttempt = 0; networkAttempt < 2; networkAttempt++) {
        const body = plist.build({
            appleId: email,
            attempt: flowAttempt,
            guid,
            password: `${password}${String(code || '').replaceAll(' ', '')}`,
            rmp: '0',
            why: 'signIn',
        });
        for (const endpoint of endpoints) {
            res = postStoreAuth(endpoint, headers, body, jar);
            if (process.env.IPA_DEBUG_AUTH === '1') {
                const contentType = headerValue(res?.headers || '', 'content-type');
                const location = headerValue(res?.headers || '', 'location');
                console.error(`[auth:store-password] flow=${flowAttempt} retry=${networkAttempt + 1} endpoint=${endpoint} status=${res?.status || 0} bytes=${res?.body?.length || 0} contentType=${contentType} location=${location ? 'yes' : 'no'}`);
            }
            // ipatool v2.3.2: native auth may return an HTML/non-plist body with
            // 403, or an empty 204/404/503. Retry the same plist body against the
            // legacy MZFinance endpoint instead of trying to parse that response.
            if (!shouldFallbackStoreAuth(res)) break;
        }
        if (!shouldFallbackStoreAuth(res)) break;
    }

    if (!res?.body?.length) {
        throw storeAuthRejected(res);
    }

    const parsed = parsePlistLoose(res.body, t('ctx_store_login_resp'));
    if (String(parsed.failureType || '') === '' && !code && parsed.customerMessage === 'MZFinance.BadLogin.Configurator_message') {
        throw needs2faError();
    }
    if (String(parsed.failureType || '') === '5005') {
        throw new Error(t('wrong_code'));
    }
    if (!parsed.passwordToken || !parsed.dsPersonId) {
        throw new Error(parsed.customerMessage || t('store_token_failed'));
    }

    const storeFront = headerValue(res.headers, 'x-set-apple-store-front');
    return {parsed, storeFront, pod: podFromHeaders(res.headers)};
}

function userFromStoreAuth(email, parsed, storeFront, pod, jar) {
    const dsid = parsed.dsPersonId;
    const authHeaders = {
        'X-Dsid': dsid,
        'iCloud-DSID': dsid,
        'X-Token': parsed.passwordToken,
    };
    if (storeFront) authHeaders['X-Apple-Store-Front'] = storeFront;

    const cookieText = existsSync(jar) ? readFileSync(jar, 'utf8') : '';
    return {
        accountInfo: parsed.accountInfo || {appleId: email, address: {firstName: '', lastName: ''}},
        dsPersonId: dsid,
        passwordToken: parsed.passwordToken,
        pod: pod || '',
        authHeaders,
        cookieText,
    };
}

export async function storeLogin(email, password, code, guid, cookieText = '', pod = '') {
    const jar = path.join(tmpDir(), `store-cookies-${crypto.createHash('sha256').update(String(email || '')).digest('hex').slice(0, 12)}.txt`);
    if (cookieText) writeFileSync(jar, cookieText);
    const {parsed, storeFront, pod: newPod} = storePasswordAuthenticate(email, password, code, guid, jar);
    return userFromStoreAuth(email, parsed, storeFront, newPod || pod, jar);
}

// 主入口：返回与旧 Store.login 兼容的 user 对象。
// code 为空且账号需要 2FA 时，会先向受信任设备推送验证码，并抛出「需要双重验证码」。
export async function gsaLogin(email, password, code, guid, codeProvider = null) {
    const normalizedCode = String(code || '').replaceAll(' ', '').trim();
    const ani = await fetchAnisette();
    let {spd, status} = srpLogin(email, password, ani);
    const requires2FA = status.au === 'trustedDeviceSecondaryAuth' || status.au === 'secondaryAuth';

    if (!normalizedCode && requires2FA) {
        const pushed = send2faPush(ani, spd.adsid, spd.GsIdmsToken);
        if (!pushed) {
            const error = new Error('无法向受信任 Apple 设备请求双重认证验证码，请检查网络后重试');
            error.code = 'TWOFA_PUSH_FAILED';
            throw error;
        }
        if (typeof codeProvider !== 'function') throw needs2faError();
        code = String(await codeProvider()).replaceAll(' ', '').trim();
        if (!/^\d{6}$/.test(code)) throw new Error(t('wrong_code'));
    }

    if (requires2FA) {
        const ok = validate2fa(ani, spd.adsid, spd.GsIdmsToken, code);
        if (!ok) throw new Error(t('wrong_code'));
        ({spd, status} = srpLogin(email, password, ani));
        if (status.au) throw new Error(t('twofa_incomplete'));
    }

    debugAuthenticationShape(spd, status);

    // macOS 26.3+ performs this authenticated password intermission before a
    // commerce login. It upgrades the account's PDP state without persisting
    // the Apple account in macOS Accounts.
    const pdpResult = performPDPIntermission(password, ani, spd);
    if (pdpResult.attempted && pdpResult.status >= 500) {
        throw new Error(`Apple PDP 服务暂时不可用（HTTP ${pdpResult.status}）`);
    }

    const pet = spd.t?.['com.apple.gs.idms.pet']?.token;
    if (!pet) throw new Error(t('no_pet'));

    const jar = path.join(tmpDir(), 'store-cookies.txt');
    let storeResult;
    try {
        storeResult = storeAuthenticate(email, pet, ani, spd.adsid, spd.GsIdmsToken, guid, jar);
    } catch (error) {
        // Apple's newer commerce gateway may reject a PET used directly as the
        // Store password while still accepting the original password bound to
        // the freshly authenticated GSA/anisette identity.
        if (error?.code !== 'STORE_HTTP_REJECTED') throw error;
        storeResult = storeAuthenticate(email, password, ani, spd.adsid, spd.GsIdmsToken, guid, jar);
    }
    const {parsed, storeFront, pod} = storeResult;

    const user = userFromStoreAuth(email, parsed, storeFront, pod, jar);
    if (!parsed.accountInfo) {
        user.accountInfo = {appleId: email, address: {firstName: spd.fn || '', lastName: spd.ln || ''}};
    }
    return user;
}

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
