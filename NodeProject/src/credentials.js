export async function readCredentials(stream = process.stdin) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString('utf8').trim();
    if (!raw) throw new Error('Missing stdin credentials');

    const credentials = JSON.parse(raw);
    if (!credentials.appleAccount || !credentials.password || !credentials.sessionKey) {
        throw new Error('Incomplete stdin credentials');
    }
    return {
        appleAccount: String(credentials.appleAccount),
        password: String(credentials.password),
        code: String(credentials.code || ''),
        sessionKey: String(credentials.sessionKey),
    };
}
