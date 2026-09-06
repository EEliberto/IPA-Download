import assert from 'node:assert/strict';
import test from 'node:test';
import {randomBytes} from 'node:crypto';
import {DEFAULT_SESSION_TTL_MS, openSession, sealSession} from '../src/ipa.js';

test('encrypts Apple session data with AES-256-GCM', () => {
    const key = randomBytes(32);
    const session = {
        appleAccount: 'person@example.test',
        savedAt: Date.now(),
        user: {
            authHeaders: {'X-Token': 'secret-token', 'X-Dsid': '123'},
            cookieText: 'session-cookie=secret',
        },
    };

    const envelope = sealSession(session, key);
    const serialized = JSON.stringify(envelope);
    assert.equal(envelope.format, 'pastel-session-aes-gcm-v1');
    assert.equal(serialized.includes('secret-token'), false);
    assert.equal(serialized.includes('session-cookie'), false);
    assert.deepEqual(openSession(envelope, key), session);
});

test('rejects a session encrypted with another key', () => {
    const envelope = sealSession({savedAt: Date.now()}, randomBytes(32));
    assert.throws(() => openSession(envelope, randomBytes(32)));
});

test('uses a 30-day default session lifetime', () => {
    assert.equal(DEFAULT_SESSION_TTL_MS, 30 * 24 * 60 * 60 * 1000);
});
