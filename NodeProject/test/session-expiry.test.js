import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {isAuthFailureResponse} from '../src/client.js';

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
