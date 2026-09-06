import assert from 'node:assert/strict';
import test from 'node:test';
import {Readable} from 'node:stream';
import {readCredentials} from '../src/credentials.js';

test('reads secrets exclusively from the stdin payload', async () => {
    const input = Readable.from([JSON.stringify({
        appleAccount: 'person@example.test',
        password: 'pipe-secret',
        code: '123456',
        sessionKey: Buffer.alloc(32, 7).toString('base64'),
    })]);

    const credentials = await readCredentials(input);
    assert.equal(credentials.password, 'pipe-secret');
    assert.equal(credentials.code, '123456');
});

test('rejects incomplete stdin credentials', async () => {
    await assert.rejects(
        readCredentials(Readable.from(['{"appleAccount":"person@example.test"}'])),
        /Incomplete stdin credentials/,
    );
});
