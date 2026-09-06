import test from 'node:test';
import assert from 'node:assert/strict';
import {extractStorefrontVersionId} from '../src/catalog.js';

test('extracts the matching App Store external version identifier', () => {
    const html = String.raw`
        <script>{"buyParams":"productType=C&price=0&salableAdamId=6477489729&pricingParameters=STDQ&appExtVrsId=890788137"}</script>
        <script>{"buyParams":"productType=C&salableAdamId=123456789&appExtVrsId=111222333"}</script>
    `;
    assert.equal(extractStorefrontVersionId(html, '6477489729'), '890788137');
});

test('decodes escaped ampersands in serialized storefront data', () => {
    const html = String.raw`{"buyParams":"productType=C\u0026salableAdamId=42\u0026appExtVrsId=99887766"}`;
    assert.equal(extractStorefrontVersionId(html, '42'), '99887766');
});
