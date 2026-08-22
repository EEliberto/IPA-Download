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

const _endpoints = {
    AppInfo: {
        url: (guid, pod) => `https://${podPrefix(pod)}buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=${guid}`,
        buildBody: ({appIdentifier, appVerId, guid}) => ({
            creditDisplay: '',
            guid,
            salableAdamId: appIdentifier,
            ...(appVerId && {externalVersionId: appVerId}),
        }),
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
            return parsePlistLoose(res.body, t('ctx_resp'));
        } catch (error) {
            const e = new Error(`${prefix}${t('bad_format_suffix', {message: error.message})}`);
            e.code = 'STORE_FAIL';
            throw e;
        }
    }

    static async AppInfo(appIdentifier, appVerId, authContext) {
        const endpoint = _endpoints.AppInfo;
        const url = endpoint.url(this.guid, authContext?.pod);
        const dsid = authContext?.authHeaders?.['X-Dsid'];
        // 与 ipatool 一致：下载信息请求仅带 DSID 头 + 会话 cookie（不带 X-Token / storefront）。
        const headers = {
            'User-Agent': STORE_USER_AGENT,
            'Content-Type': 'application/x-apple-plist',
            'iCloud-DSID': dsid,
            'X-Dsid': dsid,
        };
        const parsedResp = this.#storePost(t('label_download_app'), url, endpoint.buildBody({appIdentifier, appVerId, guid: this.guid}), headers, authContext);
        if (parsedResp.failureType === '5002') {
            const e = new Error(t('appinfo_busy'));
            e.code = 'APPINFO_FAIL';
            throw e;
        }
        if (isAuthFailureResponse(parsedResp.failureType, parsedResp.customerMessage)) {
            throw tokenExpiredError();
        }
        if (parsedResp.customerMessage) {
            const e = new Error(t('appinfo_custom', {msg: parsedResp.customerMessage}));
            e.code = 'APPINFO_FAIL';
            throw e;
        }
        if (!parsedResp.songList?.[0]) {
            const e = new Error(t('appinfo_nodata'));
            e.code = 'APPINFO_FAIL';
            throw e;
        }
        return parsedResp;
    }

    static async purchase(appid, appVerId, authContext) {
        const endpoint = _endpoints.purchase;
        const url = endpoint.url(authContext?.pod);
        // 先用 App Store 定价参数 STDQ，失败再用 Apple Arcade 的 GAME 重试一次。
        const headers = {
            'User-Agent': STORE_USER_AGENT,
            'Content-Type': 'application/x-apple-plist',
            ...(authContext?.authHeaders || {}),
        };
        let lastMsg = '';
        for (const pricingParameters of ['STDQ', 'GAME']) {
            const parsedResp = this.#storePost(t('label_purchase'), url, endpoint.buildBody({appid, appVerId, guid: this.guid, pricingParameters}), headers, authContext);
            if (parsedResp.status === 0 || parsedResp.failureType === '5002' || parsedResp.failureType === '2040') {
                let message = t('lic_success');
                if (parsedResp.failureType === '5002' || parsedResp.failureType === '2040') message = t('lic_in_library');
                else if (parsedResp.status === 0) message = t('lic_new');
                return {...parsedResp, _state: 'success', customerMessage: message};
            }
            if (isAuthFailureResponse(parsedResp.failureType, parsedResp.customerMessage)) {
                throw tokenExpiredError();
            }
            lastMsg = parsedResp.customerMessage || t('lic_fail_msg');
        }
        const e = new Error(t('license_failed', {msg: lastMsg}));
        e.code = 'LICENSE_FAIL';
        throw e;
    }
}

export {Store};
