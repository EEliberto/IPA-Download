#!/bin/sh
set -eu

resources="${CODESIGNING_FOLDER_PATH}/Contents/Resources"
stage="${DERIVED_FILE_DIR}/NodeRuntime/NodeProject"
node_archive="${SRCROOT}/node/bin/node.gz"
node="${DERIVED_FILE_DIR}/NodeRuntime/node"
npm_cli="${SRCROOT}/node/lib/node_modules/npm/bin/npm-cli.js"
lock_copy="${stage}/package-lock.json"

mkdir -p "${stage}" "${resources}/node/bin"

if [ ! -x "${node}" ] || [ "${node_archive}" -nt "${node}" ]; then
    /usr/bin/gzip -dc "${node_archive}" > "${node}"
    chmod 755 "${node}"
fi

if [ ! -d "${stage}/node_modules" ] || [ ! -f "${lock_copy}" ] || ! cmp -s "${SRCROOT}/NodeProject/package-lock.json" "${lock_copy}"; then
    cp "${SRCROOT}/NodeProject/package.json" "${stage}/package.json"
    cp "${SRCROOT}/NodeProject/package-lock.json" "${lock_copy}"
    (cd "${stage}" && "${node}" "${npm_cli}" ci --omit=dev)
fi

cp "${SRCROOT}/NodeProject/package.json" "${stage}/package.json"
cp "${SRCROOT}/NodeProject/package-lock.json" "${lock_copy}"
cp "${SRCROOT}/NodeProject/main.js" "${stage}/main.js"
rsync -a --delete --exclude '.DS_Store' "${SRCROOT}/NodeProject/src/" "${stage}/src/"
rsync -a --delete --exclude '.DS_Store' "${stage}/" "${resources}/NodeProject/"

cp "${node}" "${resources}/node/bin/node"
chmod 755 "${resources}/node/bin/node"

sap_arch="${NATIVE_ARCH_ACTUAL:-arm64}"
xcrun --sdk macosx clang -fobjc-arc -fblocks -arch "${sap_arch}" \
    -mmacosx-version-min="${MACOSX_DEPLOYMENT_TARGET}" -framework Foundation \
    "${SRCROOT}/Scripts/SAPSigner.m" -o "${resources}/sap-signer"
chmod 755 "${resources}/sap-signer"

# Sign from the innermost executable outward. sap-signer does not execute JIT;
# Node is a separate process and receives the sole runtime exception it needs.
codesign --force --sign - "${resources}/sap-signer"
codesign --force --sign - --options runtime \
    --entitlements "${SRCROOT}/Scripts/NodeJIT.entitlements" \
    "${resources}/node/bin/node"

# Exercise V8 after the final signature is applied. This catches a missing JIT
# entitlement rather than merely asserting that the plist contains a key.
"${resources}/node/bin/node" -e '
function hot(value) { return (value * 3 + 7) ^ 0x55; }
let result = 0;
for (let index = 0; index < 250000; index += 1) result = hot(result + index);
if (!process.versions.node.startsWith("24.") || !Number.isInteger(result)) process.exit(1);
'

sh "${SRCROOT}/Scripts/PatchSparkleLocalizations.sh" "${CODESIGNING_FOLDER_PATH}"
sparkle_framework="${CODESIGNING_FOLDER_PATH}/Contents/Frameworks/Sparkle.framework"
if [ -d "${sparkle_framework}" ]; then
    codesign --force --sign - "${sparkle_framework}"
fi
xattr -cr "${CODESIGNING_FOLDER_PATH}" || true
touch "${DERIVED_FILE_DIR}/pastel-node-runtime.stamp"
