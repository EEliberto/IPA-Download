import plist from 'plist';
import {storeLogin, curlRequest, parsePlistLoose, STORE_USER_AGENT, cleanup} from './gsa.js';
import {getDeviceGuid} from './device.js';
import {t} from './i18n.js';

class ApiError extends Error {
    constructor(message, failureType, customerMessage) {
        super(message);
        this.name = 'ApiError';
        this.failureType = failureType;
        this.customerMessage = customerMessage;
        if (Error.captureStackTrace) Error.captureStackTrace(this, ApiError);
    }
}

function podPrefix(pod) {
    return pod ? `p${pod}-` : '';
}

function tokenExpiredError() {
    const e = new Error('password token is expired');
    e.code = 'TOKEN_EXPIRED';
    return e;
}

function isPasswordTokenExpiredMessage(message) {
    return /Your password has changed\.?|password token is expired/i.test(String(message || ''));
}

// ipaverse treats these StoreServices failures as authentication/session
// failures. Apple does not consistently include an English error message, so
// relying on customerMessage alone leaves some expired sessions undetected.
const AUTH_FAILURE_TYPES = new Set(['-5000', '1008', '2002', '2034', '2042']);

export function isAuthFailureResponse(failureType, customerMessage, statusCode = 200) {
    return statusCode === 401
        || statusCode === 403
        || AUTH_FAILURE_TYPES.has(String(failureType || ''))
        || isPasswordTokenExpiredMessage(customerMessage);
}

export function appInfoFailureCode(failureType, customerMessage) {
    const type = String(failureType || '');
    if (type === '9610') return 'LICENSE_NOT_FOUND';
    if (type === '2059') return 'APPINFO_BUSY';
    if (/License not found/i.test(String(customerMessage || ''))) return 'LICENSE_NOT_FOUND';
    return type || customerMessage ? 'APPINFO_FAIL' : '';
}

const _endpoints = {
    AppInfo: {
        url: (guid, pod) => `https://${podPrefix(pod)}buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=${guid}`,
        buildBody: ({appIdentifier, appVerId, guid, redownload = false}) => ({
            creditDisplay: '',
            guid,
            salableAdamId: appIdentifier,
            ...(!redownload && {serialNumber: '0'}),
            ...(appVerId && {[redownload ? 'appExtVrsId' : 'externalVersionId']: appVerId}),
        }),
    },
    Redownload: {
        url: (guid) => `https://downloaddispatch.itunes.apple.com/r/redownload?guid=${guid}`,
    },
    purchase: {
        url: (pod) => `https://${podPrefix(pod)}buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/buyProduct`,
        buildBody: ({appid, appVerId, guid, pricingParameters = 'STDQ'}) => ({
            appExtVrsId: appVerId || '0',
            buyWithoutAuthorization: 'true',
            hasAskedToFulfillPreorder: 'true',
            hasDoneAgeCheck: 'true',
            guid,
            needDiv: '0',
            origPage: `Software-${appid}`,
            origPageLocation: 'Buy',
            price: '0',
            pricingParameters,
            productType: 'C',
            salableAdamId: appid,
        }),
    },
};

class Store {
    static get guid() {
        return getDeviceGuid();
    }

    static cleanup() {
        cleanup();
    }

    // 与 Asspp 一样直接使用 StoreServices 登录；此活动路径不调用
    // GSA/Anisette，因此不会创建模拟 Mac 设备记录。
    static async login(email, password, mfa, previousSession = null) {
        try {
            return await storeLogin(email, password, mfa, this.guid, previousSession?.cookieText || '', previousSession?.pod || '');
        } catch (error) {
            const msg = error.message || String(error);
            if (error.code === 'AUTH_OR_2FA') {
                const e = new Error(t('login_auth_or_2fa'));
                e.code = 'AUTH_OR_2FA';
                throw e;
            }
            // 2FA 检测用稳定的 error.code（不依赖文案语言）；保留中文 includes 作为兜底。
            if (error.code === 'NEEDS_2FA' || msg.includes('需要双重验证码')) {
                const e = new Error(t('login_2fa'));
                e.code = 'NEEDS_2FA';
                throw e;
            }
            throw new Error(t('login_auth_failed', {msg}));
        }
    }

    // 调用 StoreServices 私有接口（volumeStoreDownloadProduct / buyProduct），经系统代理走 curl，
    // 并复用 authenticate 阶段种下的会话 cookie（volumeStoreDownloadProduct 依赖该会话）。
    static #storePost(prefix, url, bodyObj, headers, authContext) {
        const body = plist.build(bodyObj);
        let res = null;
        for (let attempt = 1; attempt <= 3; attempt++) {
            res = curlRequest('POST', url, {headers, body, follow: true, timeout: 60, jar: authContext?.cookieJar || null});
            if (res.status !== 0) break;
        }
        if (!res || res.status === 0) {
            const e = new Error(`${prefix}${t('net_failed_suffix')}`);
            e.code = 'STORE_FAIL';
            throw e;
        }
        if (isAuthFailureResponse('', '', res.status)) throw tokenExpiredError();
        try {
            return {...parsePlistLoose(res.body, t('ctx_resp')), _httpStatus: res.status};
        } catch (error) {
            const e = new Error(`${prefix}${t('bad_format_suffix', {message: error.message})}`);
            e.code = 'STORE_FAIL';
            throw e;
        }
    }

    static async AppInfo(appIdentifier, appVerId, authContext, {listVersions = false} = {}) {
        const endpoint = _endpoints.AppInfo;
        const dsid = authContext?.authHeaders?.['X-Dsid'];
        // 与 ipatool 一致：下载信息请求仅带 DSID 头 + 会话 cookie（不带 X-Token / storefront）。
        const headers = {
            'User-Agent': STORE_USER_AGENT,
            'Content-Type': 'application/x-apple-plist',
            'iCloud-DSID': dsid,
            'X-Dsid': dsid,
        };
        let parsedResp = this.#storePost(
            t('label_download_app'),
            endpoint.url(this.guid, authContext?.pod),
            endpoint.buildBody({appIdentifier, appVerId, guid: this.guid}),
            headers,
            authContext
        );
        // Asspp/ApplePackage 的兼容路径：Apple 会对部分第三方 App 在主端点
        // 返回 5002，近期也会返回 status=0 + 空 songList。两种情况都改走
        // downloaddispatch 的 redownload 端点；Gemini 等 App 的历史数据在这里可用。
        if (String(parsedResp.failureType || '') === '5002' || !parsedResp.songList?.[0]) {
            const redownload = _endpoints.Redownload;
            parsedResp = this.#storePost(
                t('label_download_app'),
                redownload.url(this.guid),
                endpoint.buildBody({appIdentifier, appVerId, guid: this.guid, redownload: true}),
                headers,
                authContext
            );
        }
        const failureCode = appInfoFailureCode(parsedResp.failureType, parsedResp.customerMessage);
        if (failureCode === 'APPINFO_BUSY') {
            const e = new Error(t('appinfo_busy'));
            e.code = failureCode;
            throw e;
        }
        if (isAuthFailureResponse(parsedResp.failureType, parsedResp.customerMessage)) {
            throw tokenExpiredError();
        }
        if (parsedResp.customerMessage) {
            const e = new Error(t('appinfo_custom', {msg: parsedResp.customerMessage}));
            e.code = failureCode;
            throw e;
        }
        if (!parsedResp.songList?.[0]) {
            const e = new Error(t('appinfo_nodata'));
            // Apple sometimes reports an unowned free App as status=0 with an
            // empty songList instead of failureType=9610. Only the version-list
            // path may interpret that response as a missing license candidate.
            e.code = listVersions ? 'APPINFO_EMPTY' : 'APPINFO_FAIL';
            throw e;
        }
        return parsedResp;
    }

    static async purchase(appid, appVerId, authContext) {
        const endpoint = _endpoints.purchase;
        const url = endpoint.url(authContext?.pod);
        // 对齐 ipatool：只有 2059（暂时不可用）才使用 Apple Arcade 的 GAME 参数重试。
        const headers = {
            'User-Agent': STORE_USER_AGENT,
            'Content-Type': 'application/x-apple-plist',
            ...(authContext?.authHeaders || {}),
        };
        for (const pricingParameters of ['STDQ', 'GAME']) {
            const parsedResp = this.#storePost(t('label_purchase'), url, endpoint.buildBody({appid, appVerId, guid: this.guid, pricingParameters}), headers, authContext);
            if (parsedResp.status === 0 || parsedResp.failureType === '5002' || parsedResp._httpStatus === 500) {
                let message = t('lic_success');
                if (parsedResp.failureType === '5002' || parsedResp._httpStatus === 500) message = t('lic_in_library');
                else if (parsedResp.status === 0) message = t('lic_new');
                return {...parsedResp, _state: 'success', customerMessage: message};
            }
            if (isAuthFailureResponse(parsedResp.failureType, parsedResp.customerMessage)) {
                throw tokenExpiredError();
            }
            if (parsedResp.failureType === '2059' && pricingParameters === 'STDQ') {
                continue;
            }
            const e = new Error(t('license_failed', {msg: parsedResp.customerMessage || parsedResp.failureType || t('lic_fail_msg')}));
            e.code = 'LICENSE_FAIL';
            throw e;
        }
        const e = new Error(t('license_failed', {msg: t('lic_fail_msg')}));
        e.code = 'LICENSE_FAIL';
        throw e;
    }
}

export {Store};
