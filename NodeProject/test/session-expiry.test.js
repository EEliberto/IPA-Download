import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import plist from 'plist';
import {isAuthFailureResponse} from '../src/client.js';
import {getDeviceGuid, normalizeDeviceGuid} from '../src/device.js';
import {Ipa, SESSION_FLOW_VERSION} from '../src/ipa.js';
import {
    buildLoginBody,
    buildSignedAuthenticationHeaders,
    isRetryableAuthenticationStatus,
    parseLoginResponse,
    proxyBypassListMatches,
    sendAuthenticationRequest,
    validateAuthenticationEndpoint,
} from '../src/gsa.js';

test('recognizes StoreServices HTTP authentication failures', () => {
    assert.equal(isAuthFailureResponse('', '', 401), true);
    assert.equal(isAuthFailureResponse('', '', 403), true);
    assert.equal(isAuthFailureResponse('', '', 500), false);
});

test('recognizes ipaverse session-expiry failure types', () => {
    for (const failureType of ['-5000', '1008', '2002', '2034', '2042']) {
        assert.equal(isAuthFailureResponse(failureType, '', 200), true, failureType);
    }
    assert.equal(isAuthFailureResponse('5002', 'License already exists', 200), false);
});

test('recognizes legacy password-token messages', () => {
    assert.equal(isAuthFailureResponse('', 'Your password has changed.', 200), true);
    assert.equal(isAuthFailureResponse('', 'password token is expired', 200), true);
    assert.equal(isAuthFailureResponse('', 'temporarily unavailable', 200), false);
});

test('active Store login path does not invoke GSA or Anisette', () => {
    const clientSource = readFileSync(new URL('../src/client.js', import.meta.url), 'utf8');
    const mainSource = readFileSync(new URL('../main.js', import.meta.url), 'utf8');
    assert.doesNotMatch(clientSource, /\bgsaLogin\b|fetchAnisette|IPA_NATIVE_ANISETTE/);
    assert.doesNotMatch(mainSource, /request-2fa|IPA_NATIVE_ANISETTE/);
});

test('normalizes valid device GUIDs and rejects privacy placeholders', () => {
    assert.equal(normalizeDeviceGuid('5c:9b:a6:5d:b0:cf'), '5C9BA65DB0CF');
    assert.equal(normalizeDeviceGuid('A2-B3-C4-D5-E6-F7'), 'A2B3C4D5E6F7');
    for (const invalid of [
        '020000000000',
        '02:00:00:00:00:00',
        '000000000000',
        'FFFFFFFFFFFF',
        '01:00:5E:00:00:01',
        '5C9BA65DB0CF00',
        'not-a-guid',
    ]) {
        assert.equal(normalizeDeviceGuid(invalid), '', invalid);
    }
});

test('blocks an explicitly supplied invalid device GUID before Apple authentication', () => {
    const previousGuid = process.env.IPA_DEVICE_GUID;
    try {
        process.env.IPA_DEVICE_GUID = '020000000000';
        assert.throws(() => getDeviceGuid(), (error) => {
            assert.equal(error.code, 'DEVICE_GUID_INVALID');
            assert.match(error.message, /设备 GUID/);
            return true;
        });
    } finally {
        if (previousGuid === undefined) delete process.env.IPA_DEVICE_GUID;
        else process.env.IPA_DEVICE_GUID = previousGuid;
    }
});

test('retries only transient authentication responses used by upstream ipatool', () => {
    for (const status of [204, 404, 500, 503, 599]) {
        assert.equal(isRetryableAuthenticationStatus(status), true, String(status));
    }
    for (const status of [0, 200, 302, 400, 401, 403, 429, 600]) {
        assert.equal(isRetryableAuthenticationStatus(status), false, String(status));
    }
});

test('bounds transient authentication retries and preserves the request body', () => {
    const calls = [];
    const sleeps = [];
    const body = Buffer.from('signed plist');
    const responses = [{status: 204}, {status: 503}, {status: 200, body: Buffer.from('ok')}];
    const result = sendAuthenticationRequest(
        'https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate',
        body,
        '/tmp/cookies',
        (url, sentBody, jar) => {
            calls.push({url, sentBody, jar});
            return responses[calls.length - 1];
        },
        (milliseconds) => sleeps.push(milliseconds),
    );

    assert.equal(result.status, 200);
    assert.equal(calls.length, 3);
    assert.ok(calls.every((call) => call.sentBody === body));
    assert.deepEqual(sleeps, [250, 500]);
});

test('does not retry HTTP 403 authentication rejection', () => {
    let calls = 0;
    const result = sendAuthenticationRequest(
        'https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate',
        Buffer.from('plist'),
        null,
        () => { calls += 1; return {status: 403, headers: '', body: Buffer.alloc(0)}; },
        () => assert.fail('HTTP 403 must not sleep or retry'),
    );

    assert.equal(calls, 1);
    assert.equal(result.status, 403);
});

test('accepts only Apple MZFinance authentication endpoints and pod redirects', () => {
    const base = 'https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate';
    const pod = 'https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate';
    assert.equal(validateAuthenticationEndpoint(base), base);
    assert.equal(validateAuthenticationEndpoint(pod), pod);
    for (const endpoint of [
        'http://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate',
        'https://buy.itunes.apple.com/other',
        'https://buy.itunes.apple.com.example.com/WebObjects/MZFinance.woa/wa/authenticate',
        'https://example.com/WebObjects/MZFinance.woa/wa/authenticate',
    ]) {
        assert.throws(() => validateAuthenticationEndpoint(endpoint), /认证地址/);
    }
});

test('honors standard proxy bypass host patterns', () => {
    const url = 'https://p42-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate';
    assert.equal(proxyBypassListMatches(url, 'localhost,.itunes.apple.com'), true);
    assert.equal(proxyBypassListMatches(url, '*.apple.com'), true);
    assert.equal(proxyBypassListMatches(url, 'localhost,example.com'), false);
    assert.equal(proxyBypassListMatches(url, '*'), true);
});

test('signs the exact Store authentication plist bytes for Apple', () => {
    const body = Buffer.from('<?xml version="1.0"?><plist><string>secret</string></plist>');
    let signedBody;
    const headers = buildSignedAuthenticationHeaders(
        {'Content-Type': 'application/x-apple-plist'},
        body,
        (input) => {
            signedBody = Buffer.from(input);
            return Buffer.from([0xfb, 0xef]);
        }
    );

    assert.deepEqual(signedBody, body);
    assert.equal(headers['X-Apple-ActionSignature'], '++8=');
    assert.equal(headers['Content-Type'], 'application/x-apple-plist');
});

test('rejects an empty Apple action signature', () => {
    assert.throws(
        () => buildSignedAuthenticationHeaders({}, Buffer.from('plist'), () => Buffer.alloc(0)),
        /SAP 签名为空/
    );
});

test('builds the signed Store login plist with attempt 1 and an appended auth code', () => {
    const withoutCode = plist.parse(buildLoginBody('user@example.com', 'password', '', 'GUID', 1));
    const withCode = plist.parse(buildLoginBody('user@example.com', 'password', '12 34 56', 'GUID', 1));

    assert.equal(withoutCode.attempt, '1');
    assert.equal(withoutCode.password, 'password');
    assert.equal(withCode.attempt, '1');
    assert.equal(withCode.password, 'password123456');
});

test('does not misclassify Apple Configurator bad-login response as definite 2FA', () => {
    const body = Buffer.from(plist.build({
        failureType: '',
        customerMessage: 'MZFinance.BadLogin.Configurator_message',
        'm-allowed': false,
    }));
    const result = parseLoginResponse({status: 200, headers: '', body}, 1, '');

    assert.equal(result.error?.code, 'AUTH_OR_2FA');
    assert.notEqual(result.error?.code, 'NEEDS_2FA');
});

test('reports a rejected password and verification-code combination after 2FA input', () => {
    const body = Buffer.from(plist.build({
        failureType: '',
        customerMessage: 'MZFinance.BadLogin.Configurator_message',
        'm-allowed': false,
    }));
    const result = parseLoginResponse({status: 200, headers: '', body}, 2, '123456');

    assert.equal(result.error?.code, 'AUTH_INPUT_REJECTED');
    assert.notEqual(result.error?.code, 'AUTH_OR_2FA');
});

test('rejects authentication redirects outside Apple before reposting credentials', () => {
    const result = parseLoginResponse({
        status: 302,
        headers: 'Location: https://example.com/steal\r\n',
        body: Buffer.alloc(0),
    }, 1, '');

    assert.equal(result.retry, false);
    assert.match(result.error?.message || '', /认证地址/);
});

test('reports network, SAP rejection, and disabled-account failures precisely', () => {
    const network = parseLoginResponse({status: 0, headers: '', body: Buffer.alloc(0)}, 1, '');
    const forbidden = parseLoginResponse({status: 403, headers: '', body: Buffer.alloc(0)}, 1, '');
    const disabled = parseLoginResponse({
        status: 200,
        headers: '',
        body: Buffer.from(plist.build({failureType: '', customerMessage: 'Your account is disabled.'})),
    }, 1, '');

    assert.match(network.error?.message || '', /网络请求失败/);
    assert.match(forbidden.error?.message || '', /SAP.*403/);
    assert.match(disabled.error?.message || '', /账户已被停用/);
});

test('invalidates legacy sessions and never reuses a session during forced login', async () => {
    const previousSessionDir = process.env.IPA_SESSION_DIR;
    const previousDeviceGuid = process.env.IPA_DEVICE_GUID;
    const sessionDir = mkdtempSync(join(tmpdir(), 'pastel-session-migration-'));
    const email = 'migration@example.com';
    const deviceGuid = '5C9BA65DB0CF';
    const digest = createHash('sha256').update(email).digest('hex');
    const sessionFile = join(sessionDir, `${digest}.json`);
    const session = (flowVersion) => ({
        appleAccount: email,
        deviceGuid,
        flowVersion,
        savedAt: Date.now(),
        user: {
            authHeaders: {'X-Token': 'secret-token', 'X-Dsid': '12345'},
            cookieText: 'legacy-cookie',
            pod: '6',
        },
    });

    try {
        process.env.IPA_SESSION_DIR = sessionDir;
        process.env.IPA_DEVICE_GUID = deviceGuid;
        const app = new Ipa({APPLE_ID: email, PASSWORD: 'password', CODE: ''});

        for (const legacyFlow of ['gsa-srp-v10', 'gsa-srp-v11', 'appstore-direct-v1', 'appstore-sap-v2']) {
            writeFileSync(sessionFile, JSON.stringify(session(legacyFlow)));
            assert.equal(await app.loadReusableSessionEntry(), null, legacyFlow);
            assert.equal(existsSync(sessionFile), false, legacyFlow);
        }

        writeFileSync(sessionFile, '{not-json');
        assert.equal(await app.loadReusableSessionEntry(), null);
        assert.equal(existsSync(sessionFile), false);

        writeFileSync(sessionFile, JSON.stringify(session(SESSION_FLOW_VERSION)));
        assert.equal((await app.loadReusableSessionEntry())?.flowVersion, SESSION_FLOW_VERSION);
        assert.equal(existsSync(sessionFile), true);

        writeFileSync(sessionFile, JSON.stringify({...session(SESSION_FLOW_VERSION), deviceGuid: 'A2B3C4D5E6F7'}));
        assert.equal(await app.loadReusableSessionEntry(), null);
        assert.equal(existsSync(sessionFile), false);

        writeFileSync(sessionFile, JSON.stringify(session(SESSION_FLOW_VERSION)));
        assert.equal(await app.loadReusableSessionEntry({force: true}), null);
        assert.equal(existsSync(sessionFile), false);
    } finally {
        if (previousSessionDir === undefined) delete process.env.IPA_SESSION_DIR;
        else process.env.IPA_SESSION_DIR = previousSessionDir;
        if (previousDeviceGuid === undefined) delete process.env.IPA_DEVICE_GUID;
        else process.env.IPA_DEVICE_GUID = previousDeviceGuid;
        rmSync(sessionDir, {recursive: true, force: true});
    }
});
