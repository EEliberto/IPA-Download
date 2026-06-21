import 'dotenv/config';
import {Ipa} from './src/ipa.js';
import {featuredApps, fetchVersions, lookupApp, searchApps} from './src/catalog.js';
import {t} from './src/i18n.js';

function requiredEnv(name) {
    const value = process.env[name];
    if (!value) {
        throw new Error(t('missing_config', {name}));
    }
    return value;
}

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i += 1) {
        const value = argv[i];
        if (!value.startsWith('--')) continue;

        const equalIndex = value.indexOf('=');
        if (equalIndex > -1) {
            args[value.slice(2, equalIndex)] = value.slice(equalIndex + 1);
            continue;
        }

        const key = value.slice(2);
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
            args[key] = next;
            i += 1;
        } else {
            args[key] = 'true';
        }
    }
    return args;
}

function printJSON(value) {
    process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function runCommand(command, args) {
    switch (command) {
    case 'search': {
        const query = args.query || args.term || '';
        if (!query.trim()) throw new Error(t('missing_query'));
        const result = await searchApps(query, {
            country: args.country || 'cn',
            platform: args.platform || 'iphone',
            limit: Number(args.limit || 30),
        });
        printJSON(result);
        return;
    }
    case 'lookup': {
        const appId = args.id || args.appid || args.appId || '';
        if (!appId.trim()) throw new Error(t('missing_appid'));
        const result = await lookupApp(appId, {country: args.country || 'cn', platform: args.platform || 'iphone'});
        printJSON(result);
        return;
    }
    case 'featured': {
        const result = await featuredApps({
            country: args.country || 'cn',
            platform: args.platform || 'iphone',
            limit: Number(args.limit || 30),
            offset: Number(args.offset || 0),
        });
        printJSON(result);
        return;
    }
    case 'versions': {
        const appId = args.id || args.appid || args.appId || '';
        if (!appId.trim()) throw new Error(t('missing_appid'));
        const result = await fetchVersions(appId, {provider: args.provider || 'auto'});
        printJSON(result);
        return;
    }
    default:
        throw new Error(t('unknown_command', {command}));
    }
}

(async () => {
    try {
        const command = process.argv[2];
        if (command) {
            await runCommand(command, parseArgs(process.argv.slice(3)));
            return;
        }

        const app = new Ipa({
            APPLE_ID: requiredEnv('APPLE_ID'),
            PASSWORD: requiredEnv('APPLE_PWD'),
            CODE: process.env.APPLE_CODE || '',
        });

        // 校验账户模式：优先复用本地会话；没有会话时才登录，避免每次编辑/验证账号都触发新设备登录。
        if (process.env.IPA_VALIDATE_LOGIN) {
            await app.login();
            const storefront = String(app.user?.authHeaders?.['X-Apple-Store-Front'] || '').split('-')[0];
            const addr = app.user?.accountInfo?.address || {};
            printJSON({ok: true, storefront, firstName: addr.firstName || '', lastName: addr.lastName || ''});
            console.log(t('all_done'));
            return;
        }

        await app.login();

        // 兜底模式：只登录并从 Apple 元数据取版本 ID 列表，不下载。
        if (process.env.IPA_LIST_VERSION_IDS) {
            const result = await app.listVersionIds(requiredEnv('DOWNLOAD_APPID'));
            printJSON(result);
            console.log(t('all_done'));
            return;
        }

        await app.run({
            dir: process.env.DOWNLOAD_DIR || './app',
            APPID: requiredEnv('DOWNLOAD_APPID'),
            appVerId: process.env.DOWNLOAD_VERSION_ID || '',
        });

        console.log(t('all_done'));
    } catch (err) {
        console.error(err.message || String(err));
        process.exit(1);
    }
})();
