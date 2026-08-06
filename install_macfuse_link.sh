#!/bin/bash

# install the MacPorts macFUSE bundle at the system path used by libfuse.

set -u

SOURCE=${SCALPEL3_MACFUSE_SOURCE:-/opt/local/Library/Filesystems/macfuse.fs}
TARGET=${SCALPEL3_MACFUSE_TARGET:-/Library/Filesystems/macfuse.fs}

privileged() {
    if [ "${SCALPEL3_MACFUSE_NO_SUDO:-0}" = "1" ]; then
        "$@"
    else
        sudo "$@"
    fi
}

restore_target() {
    local backup=$1
    local previous_link=$2

    privileged /bin/rm -f "$TARGET" >/dev/null 2>&1 || true
    if [ -n "$backup" ]; then
        privileged /bin/mv "$backup" "$TARGET" >/dev/null 2>&1 || true
    elif [ -n "$previous_link" ]; then
        privileged /bin/ln -s "$previous_link" "$TARGET" >/dev/null 2>&1 || true
    fi
}

install_macfuse_link() {
    local backup=""
    local previous_link=""
    local resolved_source
    local resolved_target
    local timestamp

    if [ ! -d "$SOURCE/Contents" ]; then
        echo "ERROR: macFUSE bundle not found at $SOURCE." >&2
        return 1
    fi
    if [ ! -d "$(dirname "$TARGET")" ]; then
        if ! privileged /bin/mkdir -p "$(dirname "$TARGET")"; then
            echo "ERROR: Failed to create the macFUSE destination directory." >&2
            return 1
        fi
    fi

    resolved_source=$(realpath "$SOURCE") || return 1

    if [ -L "$TARGET" ]; then
        previous_link=$(/usr/bin/readlink "$TARGET") || return 1
        if ! privileged /bin/ln -sfn "$SOURCE" "$TARGET"; then
            echo "ERROR: Failed to update macFUSE link at $TARGET." >&2
            return 1
        fi
    elif [ -e "$TARGET" ]; then
        timestamp=${SCALPEL3_MACFUSE_BACKUP_TIMESTAMP:-$(date +%Y%m%d-%H%M%S)}
        backup="$TARGET.backup-$timestamp"
        while [ -e "$backup" ] || [ -L "$backup" ]; do
            sleep 1
            timestamp=$(date +%Y%m%d-%H%M%S)
            backup="$TARGET.backup-$timestamp"
        done

        echo "Preserving existing macFUSE bundle as $backup."
        if ! privileged /bin/mv "$TARGET" "$backup"; then
            echo "ERROR: Failed to preserve existing macFUSE bundle." >&2
            return 1
        fi
        if ! privileged /bin/ln -s "$SOURCE" "$TARGET"; then
            echo "ERROR: Failed to install macFUSE link; restoring previous bundle." >&2
            restore_target "$backup" "$previous_link"
            return 1
        fi
    else
        if ! privileged /bin/ln -s "$SOURCE" "$TARGET"; then
            echo "ERROR: Failed to install macFUSE link at $TARGET." >&2
            return 1
        fi
    fi

    resolved_target=$(realpath "$TARGET" 2>/dev/null || true)
    if [ "$resolved_target" != "$resolved_source" ]; then
        echo "ERROR: macFUSE link verification failed; restoring previous bundle." >&2
        restore_target "$backup" "$previous_link"
        return 1
    fi

    echo "macFUSE system bundle now resolves to $resolved_target."
}

install_macfuse_link
