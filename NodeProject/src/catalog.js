import axios from 'axios';
import {t} from './i18n.js';

const catalogClient = axios.create({
    timeout: 20000,
    headers: {
        'User-Agent': 'IPA Download/1.0',
        'Accept': 'application/json',
    },
    validateStatus: (status) => status >= 200 && status < 300,
});

function asText(value) {
    if (value === undefined || value === null) return '';
    return String(value).trim();
}

function firstLine(value) {
    return asText(value).replace(/\r/g, '\n').split('\n')[0].trim();
}

function extractAppId(input) {
    const value = asText(input);
    if (!value) return '';

    const idMatch = value.match(/(?:^|[^a-zA-Z])id(\d{5,})(?:\D|$)/);
    if (idMatch) return idMatch[1];

    const plainMatch = value.match(/^\d{5,}$/);
    if (plainMatch) return value;

    return '';
}

function normalizeSearchPlatform(value) {
    const platform = asText(value).toLowerCase().replace(/[\s_-]+/g, '');
    if (platform === 'ipad' || platform === 'ipados' || platform === 'tablet') return 'ipad';
    if (platform === 'vision' || platform === 'visionpro' || platform === 'visionos' || platform === 'applevisionpro') return 'vision';
    return 'iphone';
}

function searchEntityForPlatform(platform) {
    return platform === 'ipad' ? 'iPadSoftware' : 'software';
}

function appPlatformFromItem(item, fallback = '') {
    const normalizedFallback = normalizeSearchPlatform(fallback);
    if (normalizedFallback === 'vision') return 'vision';
    const supportedDevices = Array.isArray(item?.supportedDevices) ? item.supportedDevices : [];
    const searchable = [
        ...supportedDevices,
        ...(Array.isArray(item?.features) ? item.features : []),
        item?.kind,
        item?.trackViewUrl,
    ].map(value => asText(value).toLowerCase());
    if (searchable.some(value => value.includes('vision') || value.includes('reality'))) return 'vision';
    if (normalizedFallback === 'ipad') return 'ipad';
    return 'iphone';
}

function isVisionCompatibleItem(item) {
    const supportedDevices = Array.isArray(item?.supportedDevices) ? item.supportedDevices : [];
    const searchable = [
        ...supportedDevices,
        ...(Array.isArray(item?.features) ? item.features : []),
        item?.kind,
        item?.trackViewUrl,
    ].map(value => asText(value).toLowerCase());

    return searchable.some(value => value.includes('vision') || value.includes('reality'));
}

function normalizeApp(item, source = 'apple', platform = '') {
    return {
        id: asText(item.trackId),
        name: asText(item.trackName || item.trackCensoredName),
        artistName: asText(item.artistName || item.sellerName),
        bundleId: asText(item.bundleId),
        version: asText(item.version),
        minimumOsVersion: asText(item.minimumOsVersion),
        price: asText(item.formattedPrice || item.price),
        fileSizeBytes: asText(item.fileSizeBytes),
        artworkUrl: asText(item.artworkUrl100 || item.artworkUrl60 || item.artworkUrl512),
        trackViewUrl: asText(item.trackViewUrl),
        currentVersionReleaseDate: asText(item.currentVersionReleaseDate || item.releaseDate),
        source,
        platform: appPlatformFromItem(item, platform),
    };
}

function normalizeRSSApp(item, source = 'apple-rss') {
    return {
        id: asText(item.id),
        name: asText(item.name),
        artistName: asText(item.artistName),
        bundleId: '',
        version: '',
        minimumOsVersion: '',
        price: '',
        fileSizeBytes: '',
        artworkUrl: asText(item.artworkUrl100),
        trackViewUrl: asText(item.url),
        currentVersionReleaseDate: asText(item.releaseDate),
        source,
        platform: normalizeSearchPlatform(source),
    };
}

function normalizeLegacyRSSApp(item, source = 'apple-rss') {
    const images = Array.isArray(item?.['im:image']) ? item['im:image'] : [];
    const largestImage = images[images.length - 1] || {};
    const id = asText(item?.id?.attributes?.['im:id']);
    const link = asText(item?.link?.attributes?.href || item?.id?.label);

    return {
        id,
        name: asText(item?.['im:name']?.label),
        artistName: asText(item?.['im:artist']?.label),
        bundleId: asText(item?.id?.attributes?.['im:bundleId']),
        version: '',
        minimumOsVersion: '',
        price: asText(item?.['im:price']?.label),
        fileSizeBytes: '',
        artworkUrl: asText(largestImage?.label),
        trackViewUrl: link,
        currentVersionReleaseDate: asText(item?.['im:releaseDate']?.label),
        source,
        platform: normalizeSearchPlatform(source),
    };
}

function extractAppleAppIdsFromHTML(html) {
    const ids = [];
    const seen = new Set();
    const text = asText(html);
    const patterns = [
        /https:\/\/apps\.apple\.com\/[^"'/?#]+\/app\/[^"'?#]*\/id(\d{5,})(?=[?"'#])/g,
        /\/app\/[^"'?#]*\/id(\d{5,})(?=[?"'#])/g,
    ];

    for (const pattern of patterns) {
        let match;
        while ((match = pattern.exec(text)) !== null) {
            const id = match[1];
            if (!id || seen.has(id)) continue;
            seen.add(id);
            ids.push(id);
        }
    }

    return ids;
}

async function fetchVisionAppIDs({country = 'cn', term = ''} = {}) {
    const cleanCountry = asText(country).toLowerCase() || 'cn';
    const cleanTerm = asText(term);
    const url = cleanTerm
        ? `https://apps.apple.com/${cleanCountry}/vision/search?term=${encodeURIComponent(cleanTerm)}`
        : `https://apps.apple.com/${cleanCountry}/vision/apps-and-games`;
    const {data} = await catalogClient.get(url, {
        headers: {
            'Accept': 'text/html,application/xhtml+xml',
        },
    });
    return extractAppleAppIdsFromHTML(data);
}

async function lookupAppsByIds(ids, {country = 'cn', platform = 'iphone'} = {}) {
    if (!ids.length) return [];
    const cleanPlatform = normalizeSearchPlatform(platform);

    const {data} = await catalogClient.get('https://itunes.apple.com/lookup', {
        params: {
            id: ids.join(','),
            country,
            entity: searchEntityForPlatform(cleanPlatform),
        },
    });

    let rawResults = Array.isArray(data.results) ? data.results : [];
    if (cleanPlatform === 'vision') {
        const visionResults = rawResults.filter(isVisionCompatibleItem);
        if (visionResults.length) rawResults = visionResults;
    }
    const apps = rawResults.map(item => normalizeApp(item, 'apple', cleanPlatform));
    const byId = new Map(apps.map(app => [app.id, app]));
    return ids.map(id => byId.get(id)).filter(Boolean);
}

// 查询 App 是否免费（用于「付费且未购买的 App 不主动申请购买许可」的兜底判断）。
// 返回 {isFree, formattedPrice}，查不到时返回 null（调用方自行决定默认策略）。
async function appPriceInfo(appId, {country = 'us'} = {}) {
    try {
        const {data} = await catalogClient.get('https://itunes.apple.com/lookup', {
            params: {id: appId, country, entity: 'software'},
        });
        const item = Array.isArray(data.results) ? data.results[0] : null;
        if (!item) return null;
        const numericPrice = Number(item.price);
        const formatted = asText(item.formattedPrice);
        const isFree = (Number.isFinite(numericPrice) && numericPrice <= 0)
            || (formatted !== '' && !/\d/.test(formatted));
        return {isFree, formattedPrice: formatted};
    } catch {
        return null;
    }
}

async function lookupApp(appId, {country = 'cn', platform = 'iphone'} = {}) {
    const cleanPlatform = normalizeSearchPlatform(platform);
    const {data} = await catalogClient.get('https://itunes.apple.com/lookup', {
        params: {
            id: appId,
            country,
            entity: searchEntityForPlatform(cleanPlatform),
        },
    });

    let rawResults = Array.isArray(data.results) ? data.results : [];
    if (cleanPlatform === 'vision') {
        const visionResults = rawResults.filter(isVisionCompatibleItem);
        if (visionResults.length) rawResults = visionResults;
    }
    const results = rawResults.map(item => normalizeApp(item, 'apple', cleanPlatform));
    return {
        queryType: 'lookup',
        count: results.length,
        results,
    };
}

async function searchApps(term, {country = 'cn', platform = 'iphone', limit = 30} = {}) {
    const cleanPlatform = normalizeSearchPlatform(platform);
    const cleanLimit = Math.max(1, Math.min(Number(limit) || 30, 200));
    const appId = extractAppId(term);
    if (appId) {
        return lookupApp(appId, {country, platform: cleanPlatform});
    }

    if (cleanPlatform === 'vision') {
        const ids = await fetchVisionAppIDs({country, term});
        const detailed = await lookupAppsByIds(ids, {country, platform: cleanPlatform});
        const results = detailed.slice(0, cleanLimit);
        return {
            queryType: 'search',
            count: detailed.length,
            results,
        };
    }

    const {data} = await catalogClient.get('https://itunes.apple.com/search', {
        params: {
            term,
            country,
            entity: searchEntityForPlatform(cleanPlatform),
            limit: cleanPlatform === 'vision' ? Math.min(cleanLimit * 4, 200) : cleanLimit,
        },
    });

    let rawResults = Array.isArray(data.results) ? data.results : [];
    if (cleanPlatform === 'vision') {
        const visionResults = rawResults.filter(isVisionCompatibleItem);
        if (visionResults.length) rawResults = visionResults;
    }
    const results = rawResults.slice(0, cleanLimit).map(item => normalizeApp(item, 'apple', cleanPlatform));
    return {
        queryType: 'search',
        count: results.length,
        results,
    };
}

async function fetchRankedRSSApps(country, platform = 'iphone') {
    const cleanPlatform = normalizeSearchPlatform(platform);
    const feedNames = cleanPlatform === 'ipad'
        ? ['topfreeipadapplications', 'toppaidipadapplications']
        : ['topfreeapplications', 'toppaidapplications'];
    const feeds = feedNames.map(name => ({
        url: `https://itunes.apple.com/${country}/rss/${name}/limit=100/json`,
        legacy: true,
    }));
    const feedResponses = await Promise.allSettled(
        feeds.map(feed => catalogClient.get(feed.url).then(response => ({...response, legacy: feed.legacy})))
    );
    const apps = [];
    const seen = new Set();

    for (const response of feedResponses) {
        if (response.status !== 'fulfilled') continue;
        const data = response.value.data;
        const results = response.value.legacy
            ? (Array.isArray(data?.feed?.entry) ? data.feed.entry : [])
            : (Array.isArray(data?.feed?.results) ? data.feed.results : []);
        for (const item of results) {
            const app = response.value.legacy ? normalizeLegacyRSSApp(item) : normalizeRSSApp(item);
            if (!app.id || seen.has(app.id)) continue;
            seen.add(app.id);
            apps.push(app);
        }
    }

    if (apps.length) return apps;

    const modernFeeds = ['top-free', 'top-paid'];
    const modernResponses = await Promise.allSettled(
        modernFeeds.map(feed => catalogClient.get(`https://rss.applemarketingtools.com/api/v2/${country}/apps/${feed}/100/apps.json`))
    );

    for (const response of modernResponses) {
        if (response.status !== 'fulfilled') continue;
        const results = Array.isArray(response.value.data?.feed?.results) ? response.value.data.feed.results : [];
        for (const item of results) {
            const app = normalizeRSSApp(item);
            if (!app.id || seen.has(app.id)) continue;
            seen.add(app.id);
            apps.push(app);
        }
    }

    return apps;
}

async function featuredApps({country = 'cn', platform = 'iphone', limit = 30, offset = 0} = {}) {
    const cleanCountry = asText(country).toLowerCase() || 'cn';
    const cleanPlatform = normalizeSearchPlatform(platform);
    const cleanLimit = Math.max(1, Math.min(Number(limit) || 30, 200));
    const cleanOffset = Math.max(0, Number(offset) || 0);

    if (cleanPlatform === 'vision') {
        const ids = await fetchVisionAppIDs({country: cleanCountry});
        const pageIDs = ids.slice(cleanOffset, cleanOffset + cleanLimit);
        const results = await lookupAppsByIds(pageIDs, {country: cleanCountry, platform: cleanPlatform});
        return {
            queryType: 'featured',
            count: ids.length,
            offset: cleanOffset,
            limit: cleanLimit,
            hasMore: cleanOffset + cleanLimit < ids.length,
            results,
        };
    }

    const apps = await fetchRankedRSSApps(cleanCountry, cleanPlatform);
    const results = apps.slice(cleanOffset, cleanOffset + cleanLimit);

    // 榜单 RSS 不含体积/版本等字段，用 lookup 批量补全本页 App 的真实大小（右侧显示体积而非排名）。
    try {
        const detailed = await lookupAppsByIds(results.map(app => app.id).filter(Boolean), {country: cleanCountry, platform: cleanPlatform});
        const byId = new Map(detailed.map(app => [app.id, app]));
        for (const app of results) {
            const full = byId.get(app.id);
            if (!full) continue;
            if (!app.fileSizeBytes) app.fileSizeBytes = full.fileSizeBytes;
            if (!app.version) app.version = full.version;
            if (!app.bundleId) app.bundleId = full.bundleId;
            if (!app.price) app.price = full.price;
            if (!app.minimumOsVersion) app.minimumOsVersion = full.minimumOsVersion;
        }
    } catch {
        // lookup 失败不致命：仍返回榜单基础信息（右侧大小留空）。
    }

    return {
        queryType: 'featured',
        count: apps.length,
        offset: cleanOffset,
        limit: cleanLimit,
        hasMore: cleanOffset + cleanLimit < apps.length,
        results,
    };
}

function bytesToSize(bytes) {
    const value = Number(bytes);
    if (!Number.isFinite(value) || value <= 0) return '';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = value;
    let unitIndex = 0;
    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex += 1;
    }
    return `${size.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function normalizeVersionRecord(item, source) {
    const versionId = asText(item.external_identifier ?? item.versionId ?? item.version_id ?? item.id);
    const version = firstLine(item.bundle_version ?? item.version ?? item.bundleShortVersionString);
    const date = asText(item.created_at ?? item.createTime ?? item.updateTime ?? item.date ?? item.time);
    const sizeValue = item.size ?? item.fileSize ?? item.fileSizeBytes;
    const size = typeof sizeValue === 'number' ? bytesToSize(sizeValue) : asText(sizeValue);

    if (!versionId || !version) return null;
    if (!/\d/.test(version) || version.length > 64) return null;

    return {
        id: `${source}-${versionId}-${version}`,
        version,
        versionId,
        date,
        size,
        source,
    };
}

function dedupeVersions(records) {
    const seen = new Set();
    const result = [];
    for (const record of records) {
        const key = `${record.versionId}:${record.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        result.push(record);
    }
    return result;
}

async function fetchTimbrdVersions(appId) {
    const {data} = await catalogClient.get('https://api.timbrd.com/apple/app-version/index.php', {
        params: {id: appId},
    });

    const items = Array.isArray(data) ? data : [];
    return items
        .map(item => normalizeVersionRecord(item, 'timbrd'))
        .filter(Boolean)
        .reverse();
}

async function fetchAgzyVersions(appId) {
    const {data} = await catalogClient.get('https://app.agzy.cn/searchVersion', {
        params: {appid: appId},
    });

    const items = Array.isArray(data?.data) ? data.data : [];
    return items
        .map(item => normalizeVersionRecord(item, 'agzy'))
        .filter(Boolean);
}

async function fetchBilinVersions(appId) {
    const {data} = await catalogClient.get(`https://apis.bilin.eu.org/history/${encodeURIComponent(appId)}`);
    const items = Array.isArray(data) ? data : Array.isArray(data?.data) ? data.data : [];
    return items
        .map(item => normalizeVersionRecord(item, 'bilin'))
        .filter(Boolean);
}

async function runProvider(provider, appId) {
    switch (provider) {
    case 'timbrd':
        return fetchTimbrdVersions(appId);
    case 'agzy':
        return fetchAgzyVersions(appId);
    case 'bilin':
        return fetchBilinVersions(appId);
    default:
        throw new Error(t('unknown_provider', {provider}));
    }
}

async function fetchVersions(appId, {provider = 'auto'} = {}) {
    const providers = provider === 'auto' ? ['timbrd', 'agzy', 'bilin'] : [provider];
    const errors = [];

    for (const name of providers) {
        try {
            const versions = dedupeVersions(await runProvider(name, appId));
            if (versions.length > 0) {
                return {
                    appId: asText(appId),
                    provider: name,
                    count: versions.length,
                    versions,
                    errors,
                };
            }
            errors.push(`${name}: 没有返回历史版本`);
        } catch (error) {
            errors.push(`${name}: ${error.message || String(error)}`);
        }
    }

    return {
        appId: asText(appId),
        provider: provider === 'auto' ? 'auto' : providers[0],
        count: 0,
        versions: [],
        errors,
    };
}

export {
    extractAppId,
    featuredApps,
    appPriceInfo,
    lookupApp,
    searchApps,
    fetchVersions,
};
