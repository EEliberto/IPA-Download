import getMAC from 'getmac';
import os from 'os';
import path from 'path';
import {existsSync, mkdirSync, readFileSync, writeFileSync} from 'fs';
import {t} from './i18n.js';

const INVALID_DEVICE_GUIDS = new Set([
    '000000000000',
    '020000000000',
    'FFFFFFFFFFFF',
]);

export function normalizeDeviceGuid(value) {
    const cleaned = String(value || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
    if (cleaned.length !== 12 || INVALID_DEVICE_GUIDS.has(cleaned)) return '';
    const firstByte = Number.parseInt(cleaned.slice(0, 2), 16);
    if (!Number.isFinite(firstByte) || (firstByte & 1) !== 0) return '';
    return cleaned;
}

function systemGuid() {
    try {
        return normalizeDeviceGuid(getMAC());
    } catch {
        return '';
    }
}

function invalidDeviceGuidError() {
    const error = new Error(t('device_guid_invalid'));
    error.code = 'DEVICE_GUID_INVALID';
    return error;
}

function supportDir() {
    if (process.env.IPA_DEVICE_DIR) return process.env.IPA_DEVICE_DIR;
    if (process.env.IPA_SESSION_DIR) return path.dirname(process.env.IPA_SESSION_DIR);
    if (process.platform === 'darwin') {
        return path.join(os.homedir(), 'Library', 'Application Support', 'Pastel');
    }
    if (process.platform === 'win32') {
        return path.join(process.env.APPDATA || os.homedir(), 'Pastel');
    }
    return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'Pastel');
}

function guidFile() {
    return path.join(supportDir(), 'device-guid.txt');
}

export function getDeviceGuid() {
    if (process.env.IPA_DEVICE_GUID !== undefined) {
        const envGuid = normalizeDeviceGuid(process.env.IPA_DEVICE_GUID);
        if (!envGuid) throw invalidDeviceGuidError();
        return envGuid;
    }

    const file = guidFile();
    try {
        if (existsSync(file)) {
            const saved = normalizeDeviceGuid(readFileSync(file, 'utf8'));
            if (saved) return saved;
        }
    } catch {
        // Fall through and regenerate.
    }

    const guid = systemGuid();
    if (!guid) throw invalidDeviceGuidError();
    try {
        mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
        writeFileSync(file, `${guid}\n`, {mode: 0o600});
    } catch {
        // The Swift host normally provides and persists the GUID. Standalone
        // callers can still use the stable system value for this process.
    }
    return guid;
}
