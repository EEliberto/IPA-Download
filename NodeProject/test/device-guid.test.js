import assert from 'node:assert/strict';
import test from 'node:test';
import {normalizeDeviceGuid} from '../src/device.js';

test('rejects privacy placeholders and invalid hardware identifiers', () => {
    for (const value of [
        '00:00:00:00:00:00',
        '02:00:00:00:00:00',
        'FF:FF:FF:FF:FF:FF',
        '01:23:45:67:89:AB',
        'A2:11:22:33:44',
        'A2:11:22:33:44:55:66',
    ]) {
        assert.equal(normalizeDeviceGuid(value), '');
    }
});

test('normalizes a valid unicast hardware identifier', () => {
    assert.equal(normalizeDeviceGuid('a2:11:22:33:44:55'), 'A21122334455');
});
