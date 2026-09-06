import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {mergeParts} from '../src/downloader.js';

test('mergeParts resolves only after the complete IPA is flushed', async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'pastel-merge-test-'));
    const out = path.join(dir, 'result.ipa');
    try {
        const chunks = [Buffer.alloc(2 * 1024 * 1024, 0x41), Buffer.alloc(2 * 1024 * 1024, 0x42)];
        await Promise.all(chunks.map((chunk, index) => writeFile(path.join(dir, `part_${index}`), chunk)));

        await mergeParts({out, dir, parts: chunks.length});

        const merged = await readFile(out);
        assert.equal(merged.length, chunks.reduce((total, chunk) => total + chunk.length, 0));
        assert.deepEqual(merged.subarray(0, 16), chunks[0].subarray(0, 16));
        assert.deepEqual(merged.subarray(chunks[0].length, chunks[0].length + 16), chunks[1].subarray(0, 16));
    } finally {
        await rm(dir, {recursive: true, force: true});
    }
});

test('normal downloads reuse the existing license without calling buyProduct', () => {
    const source = readFileSync(new URL('../src/ipa.js', import.meta.url), 'utf8');
    const runDownload = source.match(/async runDownload\([\s\S]*?\n    async run\(/)?.[0] || '';
    assert.notEqual(runDownload, '');
    assert.doesNotMatch(runDownload, /Store\.purchase\(/);
    assert.match(runDownload, /const song = await this\.info\(APPID, appVerId\)/);
});
