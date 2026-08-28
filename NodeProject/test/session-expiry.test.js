import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import plist from 'plist';
import {isAuthFailureResponse} from '../src/client.js';
import {
    buildLoginBody,
    buildSignedAuthenticationHeaders,
    parseLoginResponse,
    shouldRetryWithLegacyAuthenticate,
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

test('falls back from native authentication statuses used by ipatool', () => {
    for (const status of [204, 403, 404, 503]) {
        assert.equal(shouldRetryWithLegacyAuthenticate('https://auth.itunes.apple.com/auth/v1/native/fast/', status), true, String(status));
    }
    for (const status of [0, 200, 302, 401, 429, 500]) {
        assert.equal(shouldRetryWithLegacyAuthenticate('https://auth.itunes.apple.com/auth/v1/native/fast/', status), false, String(status));
    }
    assert.equal(shouldRetryWithLegacyAuthenticate('https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate', 403), false);
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
