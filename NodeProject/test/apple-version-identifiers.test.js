import test from 'node:test';
import assert from 'node:assert/strict';
import {versionIdentifiersFromSong} from '../src/ipa.js';

test('reads Apple version identifiers from current and legacy response shapes', () => {
    assert.deepEqual(versionIdentifiersFromSong({
        metadata: {
            softwareVersionExternalIdentifiers: [123, '456', {externalVersionId: '789'}],
            softwareVersionExternalIdentifier: 789,
        },
    }), ['123', '456', '789']);

    assert.deepEqual(versionIdentifiersFromSong({
        softwareVersionExternalIdentifiers: [{softwareVersionExternalIdentifier: 111}, {versionId: '222'}],
    }), ['111', '222']);
});
