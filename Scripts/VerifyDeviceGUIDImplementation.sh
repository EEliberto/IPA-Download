#!/bin/sh
set -eu

source_file=${1:-"${SRCROOT}/Pastel/PastelApp.swift"}
implementation=$(sed -n '/^private enum DeviceGUIDStore {/,/^}/p' "$source_file")

require() {
    printf '%s\n' "$implementation" | grep -Fq "$1" || {
        echo "Device GUID safety check failed: missing $1" >&2
        exit 1
    }
}

reject() {
    if printf '%s\n' "$implementation" | grep -Fq "$1"; then
        echo "Device GUID safety check failed: forbidden $1" >&2
        exit 1
    fi
}

require 'static func current() throws -> String'
require '020000000000'
require 'NET_RT_IFLIST'
require 'sysctl('
require 'SecItemDelete(baseQuery as CFDictionary)'
reject '/sbin/ifconfig'
reject 'randomIdentifier'

echo 'Device GUID implementation validation passed'
