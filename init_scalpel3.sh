#!/bin/bash
#
# Build script for scalpel3 on macOS and Linux. scalpel3 can also be
# run inside WSL under Windows, but native Windows builds are not
# currently supported.
#
# Written by Golden G. Richard III (@nolaforensix), Karley Waguespack, and Sam
# Hildebrand, 2021-2026.
#
# scalpel3 works only on 64-bit Linux and Mac platforms.

#(don't inherit random env junk)
CPPFLAGS=""
LDFLAGS=""
LIBS=""
CFLAGS="${CFLAGS:-}"
CXXFLAGS="${CXXFLAGS:-}"

#Remove the common "poison" vars that override include/lib search order
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH \
      LIBRARY_PATH LD_LIBRARY_PATH DYLD_LIBRARY_PATH

# ONNX Runtime (C/C++) prebuilt install
ONNXRUNTIME_VERSION="${ONNXRUNTIME_VERSION:-1.26.0}"
ONNXRUNTIME_INSTALL_PREFIX="${ONNXRUNTIME_INSTALL_PREFIX:-/usr/local}"
SCALPEL3_INSTALL_CUDA=auto
SCALPEL3_ONNX_CONFIGURE_ARGS=()
ONNX_INCLUDE_FIRST=""
ONNX_LIB_FIRST=""
SCALPEL3_INSTALL_TMPDIR="${SCALPEL3_INSTALL_TMPDIR:-${XDG_CACHE_HOME:-$HOME/.cache}/scalpel3-install}"
echo "Scalpel's ONNX version: $ONNXRUNTIME_VERSION"

# Returns 0 (true) if the NVIDIA driver can enumerate at least one GPU.
has_nvidia_gpu() {
    command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1
}

# Returns 0 when Linux exposes NVIDIA display or compute hardware, even if the
# NVIDIA driver is absent or unhealthy.
has_nvidia_hardware() {
    local class device vendor

    if has_nvidia_gpu; then
        return 0
    fi

    if [ "$(uname)" != "Linux" ]; then
        return 1
    fi

    for device in /sys/bus/pci/devices/*; do
        if [ ! -r "$device/vendor" ] || [ ! -r "$device/class" ]; then
            continue
        fi
        vendor="$(cat "$device/vendor")"
        class="$(cat "$device/class")"
        if [ "$vendor" = "0x10de" ]; then
            case "$class" in
                0x03*)
                    return 0
                    ;;
            esac
        fi
    done

    return 1
}

has_apple_silicon() {
    [ "$(uname)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]
}

# Microsoft publishes the CUDA-enabled ONNX Runtime archive for Linux x86-64.
onnxruntime_cuda_prebuilt_available() {
    local arch

    arch="$(uname -m)"
    [ "$(uname)" = "Linux" ] && \
        { [ "$arch" = "x86_64" ] || [ "$arch" = "amd64" ]; } && \
        has_nvidia_gpu
}

onnxruntime_coreml_available() {
    local libdir dylib

    libdir="${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    dylib="$(ls -1 "$libdir"/libonnxruntime*.dylib 2>/dev/null | head -n 1)"

    [ -n "$dylib" ] && strings "$dylib" | grep -q "CoreMLExecutionProvider"
}

onnxruntime_install_matches() {
    local marker

    marker="${ONNXRUNTIME_INSTALL_PREFIX}/lib/.scalpel3-onnxruntime-version"
    [ -f "$marker" ] && \
        [ "$(cat "$marker")" = "${ONNXRUNTIME_VERSION}:$1" ]
}

onnxruntime_notices_available() {
    local docdir

    docdir="${ONNXRUNTIME_INSTALL_PREFIX}/share/doc/onnxruntime"
    [ -f "$docdir/LICENSE" ] && \
        [ -f "$docdir/ThirdPartyNotices.txt" ]
}

onnxruntime_headers_available() {
    local header

    for header in \
        onnxruntime_c_api.h \
        onnxruntime_cxx_api.h \
        onnxruntime_cxx_inline.h \
        onnxruntime_float16.h
    do
        if [ ! -f "${ONNXRUNTIME_INSTALL_PREFIX}/include/$header" ]; then
            return 1
        fi
    done

    return 0
}

onnxruntime_required_api_available() {
    local header

    header="${ONNXRUNTIME_INSTALL_PREFIX}/include/onnxruntime_c_api.h"

    [ -f "$header" ] && \
        grep -q "ORT_API2_STATUS(AddFreeDimensionOverrideByName" "$header" && \
        grep -q "ORT_API2_STATUS(SessionOptionsAppendExecutionProvider," "$header"
}

verify_onnxruntime_accelerator_support() {
    if ! onnxruntime_headers_available; then
        echo "ERROR: Installed ONNX Runtime does not include the required C/C++ headers."
        echo "       Re-run this script to install ONNX Runtime ${ONNXRUNTIME_VERSION}."
        return 1
    fi

    if ! onnxruntime_required_api_available; then
        echo "ERROR: Installed ONNX Runtime headers do not expose APIs required by Scalpel3."
        echo "       Re-run this script to install ONNX Runtime ${ONNXRUNTIME_VERSION}."
        return 1
    fi

    if has_apple_silicon; then
        if ! onnxruntime_coreml_available; then
            echo "ERROR: Installed ONNX Runtime dylib does not appear to include CoreML support."
            echo "       Re-run this script to install ONNX Runtime ${ONNXRUNTIME_VERSION} for macOS arm64."
            return 1
        fi
    fi

    if onnxruntime_cuda_prebuilt_available && \
       ! ls "${ONNXRUNTIME_INSTALL_PREFIX}/lib"/libonnxruntime_providers_cuda* \
            >/dev/null 2>&1; then
        echo "ERROR: Installed ONNX Runtime does not include the CUDA execution provider."
        echo "       Re-run this script to install the CUDA-enabled archive."
        return 1
    fi

    return 0
}

verify_fuse3_development_files() {
    local version

    if ! command -v pkg-config >/dev/null 2>&1; then
        echo "ERROR: pkg-config is required to locate FUSE 3 development files."
        return 1
    fi

    if ! pkg-config --atleast-version=3.0 fuse3; then
        echo "ERROR: FUSE 3 development files were not installed correctly."
        echo "       pkg-config could not find fuse3 >= 3.0."
        return 1
    fi

    version=$(pkg-config --modversion fuse3) || return 1
    echo "FUSE 3 development files verified (version $version)."
    return 0
}

install_onnxruntime_prebuilt() {
    local arch docdir libdir marker notices_only os pkg root tmpdir url
    local ver_dylib ver_so

    os="$(uname)"
    if [ "$os" = "Linux" ]; then
        select_linux_onnx
        return $?
    fi
    arch="$(uname -m)"
    docdir="${ONNXRUNTIME_INSTALL_PREFIX}/share/doc/onnxruntime"
    libdir="${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    marker="$libdir/.scalpel3-onnxruntime-version"
    notices_only=0

    case "$os" in
        Darwin)
            case "$arch" in
                arm64)
                    pkg="onnxruntime-osx-arm64-${ONNXRUNTIME_VERSION}.tgz"
                    ;;
                x86_64)
                    pkg="onnxruntime-osx-x86_64-${ONNXRUNTIME_VERSION}.tgz"
                    ;;
                *)
                    echo "Unsupported macOS arch for ONNX Runtime: $arch"
                    return 1
                    ;;
            esac
            ;;
        *)
            echo "Unsupported OS for ONNX Runtime prebuilt: $os"
            return 1
            ;;
    esac

    if onnxruntime_headers_available && \
       { [ -e "$libdir/libonnxruntime.dylib" ] || \
         [ -e "$libdir/libonnxruntime.so" ] || \
         [ -e "$libdir/libonnxruntime.a" ] || \
         ls "$libdir"/libonnxruntime*.dylib >/dev/null 2>&1 || \
         ls "$libdir"/libonnxruntime*.so*  >/dev/null 2>&1; }; then

        if [ "$os" = "Darwin" ]; then
            if [ ! -e "$libdir/libonnxruntime.dylib" ]; then
                ver_dylib="$(ls -1 "$libdir"/libonnxruntime*.dylib 2>/dev/null | head -n 1)"
                if [ -n "$ver_dylib" ]; then
                    echo "Creating symlink: $libdir/libonnxruntime.dylib -> $(basename "$ver_dylib")"
                    sudo ln -sf "$(basename "$ver_dylib")" "$libdir/libonnxruntime.dylib"
                fi
            fi
        elif [ "$os" = "Linux" ]; then
            if [ ! -e "$libdir/libonnxruntime.so" ]; then
                ver_so="$(ls -1 "$libdir"/libonnxruntime.so.* 2>/dev/null | head -n 1)"
                if [ -n "$ver_so" ]; then
                    echo "Creating symlink: $libdir/libonnxruntime.so -> $(basename "$ver_so")"
                    sudo ln -sf "$(basename "$ver_so")" "$libdir/libonnxruntime.so"
                fi
            fi
        fi

        if ! onnxruntime_install_matches "$pkg"; then
            echo "Installed ONNX Runtime does not match ${ONNXRUNTIME_VERSION} (${pkg}). Reinstalling."
        elif onnxruntime_cuda_prebuilt_available && \
           ! ls "$libdir"/libonnxruntime_providers_cuda* >/dev/null 2>&1; then
            echo "ONNX Runtime headers present but CUDA provider missing. Reinstalling GPU version."
        elif ! onnxruntime_required_api_available; then
            echo "ONNX Runtime headers present but required APIs are missing. Reinstalling."
        elif has_apple_silicon && ! onnxruntime_coreml_available; then
            echo "ONNX Runtime headers present but CoreML provider missing. Reinstalling macOS arm64 version."
        elif ! onnxruntime_notices_available; then
            echo "ONNX Runtime licensing notices are missing. Restoring them."
            notices_only=1
        else
            echo "ONNX Runtime ${ONNXRUNTIME_VERSION} already installed; skipping install."
            verify_onnxruntime_accelerator_support || return 1
            return 0
        fi
    fi

    url="https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/${pkg}"

    mkdir -p "$SCALPEL3_INSTALL_TMPDIR"
    tmpdir="$(mktemp -d "$SCALPEL3_INSTALL_TMPDIR/onnxrt.XXXXXX")"
    echo "Downloading ONNX Runtime ${ONNXRUNTIME_VERSION} (${pkg})..."
    if ! curl -fL --retry 3 --retry-delay 2 "$url" -o "$tmpdir/$pkg"; then
        rm -rf "$tmpdir"
        return 1
    fi

    echo "Extracting..."
    if ! tar -xzf "$tmpdir/$pkg" -C "$tmpdir"; then
        rm -rf "$tmpdir"
        return 1
    fi

    root="$(find "$tmpdir" -maxdepth 1 -type d -name "onnxruntime-*" | head -n 1)"
    if [ -z "$root" ]; then
        echo "Failed to locate extracted ONNX Runtime directory."
        rm -rf "$tmpdir"
        return 1
    fi

    if [ ! -f "$root/LICENSE" ] || [ ! -f "$root/ThirdPartyNotices.txt" ]; then
        echo "ERROR: The ONNX Runtime archive does not contain its required licensing notices."
        rm -rf "$tmpdir"
        return 1
    fi

    echo "Installing ONNX Runtime notices -> $docdir/"
    if ! sudo mkdir -p "$docdir" || \
       ! sudo cp "$root/LICENSE" "$root/ThirdPartyNotices.txt" "$docdir/"; then
        echo "ERROR: Failed to install the ONNX Runtime licensing notices."
        rm -rf "$tmpdir"
        return 1
    fi

    if [ "$notices_only" -eq 1 ]; then
        rm -rf "$tmpdir"
        verify_onnxruntime_accelerator_support || return 1
        echo "ONNX Runtime licensing notices restored."
        return 0
    fi

    echo "Installing ONNX Runtime headers -> ${ONNXRUNTIME_INSTALL_PREFIX}/include/"
    sudo mkdir -p "${ONNXRUNTIME_INSTALL_PREFIX}/include"
    sudo cp -R "$root/include/"* "${ONNXRUNTIME_INSTALL_PREFIX}/include/"

    echo "Installing ONNX Runtime libs -> ${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    sudo mkdir -p "${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    if [ "$os" = "Darwin" ]; then
        sudo rm -f "$libdir/libonnxruntime.dylib"
    elif [ "$os" = "Linux" ]; then
        sudo rm -f "$libdir/libonnxruntime.so" \
                   "$libdir/libonnxruntime.so.1" \
                   "$libdir"/libonnxruntime_providers_*.so
    fi
    sudo cp -RP "$root/lib/"libonnxruntime* "${ONNXRUNTIME_INSTALL_PREFIX}/lib/"

    if ! ls "$libdir"/libonnxruntime*.dylib >/dev/null 2>&1 && \
       ! ls "$libdir"/libonnxruntime*.so*  >/dev/null 2>&1 && \
       ! ls "$libdir"/libonnxruntime*.a    >/dev/null 2>&1; then
        echo "ERROR: ONNX Runtime library did not install into $libdir"
        rm -rf "$tmpdir"
        return 1
    fi

    if [ "$os" = "Darwin" ]; then
        if [ ! -e "$libdir/libonnxruntime.dylib" ] && [ ! -e "$libdir/libonnxruntime.a" ]; then
            ver_dylib="$libdir/libonnxruntime.${ONNXRUNTIME_VERSION}.dylib"
            if [ ! -e "$ver_dylib" ]; then
                ver_dylib="$(ls -1 "$libdir"/libonnxruntime*.dylib 2>/dev/null | tail -n 1)"
            fi
            if [ -n "$ver_dylib" ]; then
                echo "Creating symlink: $libdir/libonnxruntime.dylib -> $(basename "$ver_dylib")"
                sudo ln -sf "$(basename "$ver_dylib")" "$libdir/libonnxruntime.dylib"
            fi
        fi
    elif [ "$os" = "Linux" ]; then
        if [ ! -e "$libdir/libonnxruntime.so" ] && [ ! -e "$libdir/libonnxruntime.a" ]; then
            ver_so="$libdir/libonnxruntime.so.${ONNXRUNTIME_VERSION}"
            if [ ! -e "$ver_so" ]; then
                ver_so="$(ls -1 "$libdir"/libonnxruntime.so.* 2>/dev/null | tail -n 1)"
            fi
            if [ -n "$ver_so" ]; then
                echo "Creating symlink: $libdir/libonnxruntime.so -> $(basename "$ver_so")"
                sudo ln -sf "$(basename "$ver_so")" "$libdir/libonnxruntime.so"
            fi
        fi
        sudo ldconfig
    fi

    if ! verify_onnxruntime_accelerator_support; then
        rm -rf "$tmpdir"
        return 1
    fi

    printf '%s:%s\n' "$ONNXRUNTIME_VERSION" "$pkg" \
        | sudo tee "$marker" >/dev/null

    rm -rf "$tmpdir"
    echo "ONNX Runtime install complete."
}

select_linux_onnx() {
    local config="$CURDIR/.scalpel3_onnx.conf"
    local values=()

    python3 "$CURDIR/src/onnx_install.py" --mode "$SCALPEL3_INSTALL_CUDA" \
        --version "$ONNXRUNTIME_VERSION" --output "$config" || return 1
    mapfile -t values < <(python3 - "$config" <<'PY'
import json
import sys
with open(sys.argv[1]) as stream:
    config = json.load(stream)
for key in ("prefix", "runtime", "cuda_major", "provider"):
    print(config[key])
PY
    )
    if [ "${#values[@]}" -ne 4 ]; then
        echo "ERROR: Could not read the verified ONNX configuration." >&2
        return 1
    fi
    ONNXRUNTIME_INSTALL_PREFIX="${values[0]}"
    SCALPEL3_ONNX_PROVIDER="${values[3]}"
    SCALPEL3_ONNX_CONFIGURE_ARGS=(
        "--with-cuda-major=${values[2]}"
        "--with-scalpel3-cuda-runtime=${values[1]}"
    )
    # Keep this verified header/library pair ahead of unrelated /usr/local copies.
    ONNX_INCLUDE_FIRST="-I${values[0]}/include "
    ONNX_LIB_FIRST="-L${values[0]}/lib -Wl,-rpath,${values[0]}/lib "
}

CURDIR="$PWD"

elf_model_sha256() {
    local digest

    if command -v sha256sum >/dev/null 2>&1; then
        digest="$(sha256sum < "$1")" || return 1
    elif command -v shasum >/dev/null 2>&1; then
        digest="$(shasum -a 256 < "$1")" || return 1
    else
        echo "ERROR: ELF model verification requires sha256sum or shasum." >&2
        return 1
    fi
    printf '%s\n' "${digest%%[[:space:]]*}"
}

reconstruct_elf_onnx_model_if_needed() {
    local model_dir model chunk_dir manifest expected_hash expected_name actual_hash
    local -a parts

    model_dir="$CURDIR/src/exe_vision/unix"
    model="$model_dir/elf_unet.onnx"
    chunk_dir="$model_dir/elf_onnx"
    manifest="$chunk_dir/elf_unet.onnx.sha256"

    if [ -e "$model" ] && [ ! -f "$model" ]; then
        echo "ERROR: ELF ONNX model path is not a regular file: $model" >&2
        return 1
    fi

    if ! read -r expected_hash expected_name < "$manifest" \
        || [[ ! "$expected_hash" =~ ^[0-9a-f]{64}$ ]] \
        || [ "$expected_name" != "elf_unet.onnx" ]; then
        echo "ERROR: Missing or invalid ELF model checksum: $manifest" >&2
        return 1
    fi

    if [ -f "$model" ]; then
        actual_hash="$(elf_model_sha256 "$model")" || return 1
        if [ "$actual_hash" = "$expected_hash" ]; then
            echo "ELF ONNX model verified: $model"
            return 0
        fi
        echo "Updating ELF ONNX model to the version supplied with this checkout."
    fi

    if [ ! -d "$chunk_dir" ]; then
        echo "ERROR: ELF ONNX chunk directory not found: $chunk_dir" >&2
        return 1
    fi

    parts=("$chunk_dir"/elf_unet.onnx.part_*)
    if [ "${#parts[@]}" -eq 0 ] || [ ! -f "${parts[0]}" ]; then
        echo "ERROR: No ELF ONNX model chunks found in: $chunk_dir" >&2
        return 1
    fi

    echo "Reconstructing ELF ONNX model from ${#parts[@]} chunks..."

    # Keep an existing model intact until its replacement is verified.
    if ! (
        tmp_model="$(mktemp "$model.tmp.XXXXXX")" || exit 1
        trap 'rm -f "$tmp_model"' EXIT
        trap 'exit 1' HUP INT TERM

        if ! cat "${parts[@]}" > "$tmp_model"; then
            echo "ERROR: Failed to read ELF ONNX model chunks." >&2
            exit 1
        fi
        actual_hash="$(elf_model_sha256 "$tmp_model")" || exit 1
        if [ "$actual_hash" != "$expected_hash" ]; then
            echo "ERROR: ELF ONNX model checksum mismatch; existing model left unchanged." >&2
            echo "Check that all model chunks came from the same checkout." >&2
            exit 1
        fi
        chmod 644 "$tmp_model" && mv -f "$tmp_model" "$model"
    ); then
        return 1
    fi

    echo "ELF ONNX model reconstructed and verified: $model"
    return 0
}

if [ "${1:-}" = "--elf-model-only" ]; then
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 --elf-model-only" >&2
        exit 1
    fi
    reconstruct_elf_onnx_model_if_needed
    exit $?
fi


case "${BASH_SOURCE[0]}" in
    */*) CURDIR="$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)" ;;
    *) CURDIR="$PWD" ;;
esac
cd "$CURDIR" || exit 1
SCALPEL3_ONNX_ONLY=0
SCALPEL3_ONNX_CHECK=0
for argument in "$@"; do
    case "$argument" in
        --cuda=auto|--cuda=cpu|--cuda=12|--cuda=13)
            SCALPEL3_INSTALL_CUDA="${argument#--cuda=}"
            ;;
        --onnx-only) SCALPEL3_ONNX_ONLY=1 ;;
        --check-onnx) SCALPEL3_ONNX_CHECK=1 ;;
        --help|-h)
            echo "Usage: $0 [--cuda=auto|cpu|12|13] [--onnx-only|--check-onnx]"
            echo "       $0 --elf-model-only"
            echo "Linux: auto keeps working CUDA 12/13 libraries; otherwise CPU is explicit."
            echo "--cuda=12 or 13 installs missing libraries in your own data directory."
            echo "--cuda=cpu configures CPU inference. No NVIDIA drivers are installed or changed."
            echo "--onnx-only selects ONNX libraries without the full build."
            echo "--check-onnx checks installed libraries without downloads or configuration changes."
            exit 0
            ;;
        *) echo "Unknown option: $argument (see --help)" >&2; exit 1 ;;
    esac
done
if [ "$#" -gt 0 ] && [ "$(uname)" != "Linux" ]; then
    echo "CUDA/ONNX selection options apply only to Linux." >&2
    exit 1
fi
if [ "$SCALPEL3_ONNX_CHECK" -eq 1 ]; then
    python3 "$CURDIR/src/onnx_install.py" --check --mode "$SCALPEL3_INSTALL_CUDA" \
        --version "$ONNXRUNTIME_VERSION" --output "$CURDIR/.scalpel3_onnx.conf"
    exit $?
fi
if [ "$SCALPEL3_ONNX_ONLY" -eq 1 ]; then
    select_linux_onnx
    exit $?
fi

[[ `uname -m` =~ "64" ]] ||
    {
	echo "scalpel3 works only on 64-bit platforms.";
	exit 1;
    }

reconstruct_elf_onnx_model_if_needed || exit 1

if [ "$(uname)" == "Darwin" ]; then
    # Keep Libtool's target consistent with this native build. Its unset-target
    # default is macOS 10.0, which adds the obsolete C++ -bind_at_load flag.
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-$(sw_vers -productVersion)}"
    # Modern macOS already uses a single module; skip Libtool's obsolete probe.
    export LT_MULTI_MODULE=1
    echo "Checking whether command line tools are installed."
    xcode-select -p &> /dev/null
    if [ $? -ne 0 ]; then
	echo "Command line tools not found. Installing. This may take some time."
	touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress;
	PROD=$(softwareupdate -l | grep "\*.*Command Line" | tail -n 1 | sed 's/^[^C]* //')
	softwareupdate -i "$PROD" --verbose;
    else
	echo "Command line tools are installed."
    fi

    APPLEARCH=`uname -m`
    echo "Apple architecture is $APPLEARCH."

    # try to automatically install dependencies using either MacPorts or Homebrew
    MACPORTS_INSTALLED=""
    BREW_INSTALLED=""

    if test -f /opt/local/bin/port; then
	MACPORTS_INSTALLED=yes
    fi

    if test -f /usr/local/bin/brew || test -f /opt/homebrew/bin/brew; then
	BREW_INSTALLED=yes
    fi

    if [ "$MACPORTS_INSTALLED" == "yes" ] && [ "$BREW_INSTALLED" == "yes" ]; then
	echo "Both MacPorts and Homebrew seem to be installed. This is not recommended."
	echo "MacPorts will be used to install dependencies."
    fi

    if [ "$MACPORTS_INSTALLED" == "yes" ]; then
	echo "Using MacPorts to install dependencies. Please enter your password as required."
	echo "Updating macports..."
	sudo port selfupdate
	sudo port install automake
	sudo port install autoconf
	sudo port install libtool
	sudo port install gettext
	sudo port install openssl
	sudo port install yasm
	sudo port install libelf
	sudo port install xmlto
	sudo port install libpng
	sudo port install pcre2
	sudo port install pkgconfig
	sudo port install hdf5
	sudo port install libjpeg-turbo
	sudo port install mpg123
	sudo port install libarchive
	sudo port install bzip2
	sudo port install xz
	sudo port install zstd
	sudo port install sqlite3
	sudo port install libsdl2
	sudo port install libsdl2_image
	sudo port install libsdl2_ttf
	CPPFLAGS="-g -I /usr/local/include -I /opt/local/include"
	LDFLAGS="-L/usr/local/lib -L/opt/local/lib"
	install_onnxruntime_prebuilt || exit 1
    CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
    LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    LIBS+=" -lonnxruntime"
    LIBS+=" -larchive"
    # CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
    # # LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    # # LDFLAGS+=" -Wl,-rpath,${ONNXRUNTIME_INSTALL_PREFIX}/lib"

    elif [ "$BREW_INSTALLED" == "yes" ]; then
	echo "Using Homebrew to install dependencies. Please enter your password as required."
	brew install automake
	brew install autoconf
	brew install libtool
	brew install gettext
	brew install openssl@3
	brew install openssh
	brew install libelf
	brew install xmlto
	brew install yasm
	brew install libpng
	brew install jpeg-turbo
	brew install pcre2
	brew install pkg-config
	brew install asciidoc
	brew install docbook
	brew install hdf5
	brew install mpg123
	brew install libarchive
	brew install bzip2
	brew install xz
	brew install zstd
	brew install sqlite
	brew install sdl2
	brew install sdl2_image
	brew install sdl2_ttf

	# determine paths based on architecture
	if [ "$APPLEARCH" == "arm64" ]; then
	    CPPFLAGS="-g -I /usr/local/include -I /opt/homebrew/opt/libarchive/include -I /opt/homebrew/opt/bzip2/include -I /opt/homebrew/opt/xz/include -I /opt/homebrew/opt/zstd/include -I /opt/homebrew/opt/sqlite/include -I /opt/homebrew/include"
	    LDFLAGS="-L/usr/local/lib -L/opt/homebrew/opt/libarchive/lib -L/opt/homebrew/opt/bzip2/lib -L/opt/homebrew/opt/xz/lib -L/opt/homebrew/opt/zstd/lib -L/opt/homebrew/opt/sqlite/lib -L/opt/homebrew/lib"
	else
	    CPPFLAGS="-g -I/usr/local/include -I/usr/local/opt/libarchive/include -I/usr/local/opt/bzip2/include -I/usr/local/opt/xz/include -I/usr/local/opt/zstd/include -I/usr/local/opt/sqlite/include"
	    LDFLAGS="-L/usr/local/lib -L/usr/local/opt/libarchive/lib -L/usr/local/opt/bzip2/lib -L/usr/local/opt/xz/lib -L/usr/local/opt/zstd/lib -L/usr/local/opt/sqlite/lib"
        LIBS+=" -larchive"
	fi

	# --- ONNX Runtime (needed for ELF ONNX inference)
    install_onnxruntime_prebuilt || exit 1
	CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
    LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    LIBS+=" -lonnxruntime"

    else
		echo "Neither MacPorts nor Homebrew was detected. Dependencies will have to be installed manually."
		sleep 5
	fi

    g++ -std=c++17 -fPIC -c "$CURDIR/src/pocketfft_mdct.cpp" -o "$CURDIR/src/pocketfft_mdct.o"
    sudo g++ -dynamiclib \
    -install_name /usr/local/lib/libpocketfft_mdct.dylib \
    -o "$CURDIR/src/libpocketfft_mdct.dylib" \
    "$CURDIR/src/pocketfft_mdct.o"
    sudo cp -f "$CURDIR/src/libpocketfft_mdct.dylib" /usr/local/lib/
    sudo chmod 755 /usr/local/lib/libpocketfft_mdct.dylib

    echo "Built libpocketfft_mdct.dylib for macOS"

    fix_platform_make() {
	cp src/Makefile.am.mac src/Makefile.am
	glibtoolize --copy --force
	mkdir -p m4 build-aux
    }

    fix_debug_info() {
	dsymutil scalpel3
    }
elif [ "$(uname)" == "Linux" ]; then

    # Debian family
    if command -v apt-get >/dev/null 2>&1; then

        sudo apt-get update -q &&
        sudo apt-get install -y -q \
            build-essential python3 python3-pip cmake curl git pkg-config \
            autoconf automake libtool libtool-bin gettext nasm \
            libssl-dev zlib1g-dev libbz2-dev libzstd-dev liblzma-dev \
            libreadline-dev libsqlite3-dev libffi-dev libncurses-dev tk-dev \
            xz-utils uuid-dev libpng-dev libjpeg-dev libpcre2-dev \
            libfuse3-dev fuse3 libhdf5-dev libmpg123-dev libarchive-dev \
            libsdl2-dev libsdl2-image-dev libsdl2-ttf-dev libelf-dev \
            libiberty-dev libndctl-dev binutils-dev xmlto texinfo || exit 1

        install_onnxruntime_prebuilt || exit 1
        CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    # Fedora / RedHat family
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y \
            gcc gcc-c++ make python3 python3-pip cmake curl git which \
            autoconf automake libtool gettext gettext-devel nasm \
            openssl-devel zlib-devel bzip2-devel libzstd-devel xz-devel \
            readline-devel sqlite-devel libffi-devel ncurses-devel tk-devel \
            libuuid-devel libpng-devel libjpeg-turbo-devel pcre2-devel \
            fuse3 fuse3-devel hdf5-devel mpg123-devel libarchive-devel \
            SDL2-devel SDL2_image-devel SDL2_ttf-devel elfutils-libelf-devel \
            binutils-devel ndctl-devel pkgconf-pkg-config xmlto texinfo || exit 1

        install_onnxruntime_prebuilt || exit 1
        CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper -n install gcc gcc-c++ python3 python3-pip || exit 1
        sudo zypper -n install make
        sudo zypper -n install curl
	sudo zypper -n install cmake
        sudo zypper -n install git
        sudo zypper -n install autobuild
        sudo zypper -n install openssl
        sudo zypper -n install libopenssl-devel
        sudo zypper -n install zlib-devel
        sudo zypper -n install libbz2-devel
        sudo zypper -n install libzstd-devel
        sudo zypper -n install libreadline5
        sudo zypper -n install readline-devel
        sudo zypper -n install libsqlite3-0
        sudo zypper -n install sqlite3-devel
        sudo zypper -n install libffi7
        sudo zypper -n install libffi-devel
        sudo zypper -n install ncurses
        sudo zypper -n install ncurses-devel
        sudo zypper -n install xz
        sudo zypper -n install xz-devel
        sudo zypper -n install tk-devel
        sudo zypper -n install liblzma5
        sudo zypper -n install lzma-sdk-devel
        sudo zypper -n install uuid-devel
        sudo zypper -n install libuuid-devel
        sudo zypper -n install automake
        sudo zypper -n install gettext-runtime
        sudo zypper -n install gettext-tools
        sudo zypper -n install nasm
        sudo zypper -n install libpng16-compat-devel
        sudo zypper -n install libpng16-devel
        sudo zypper -n install libpng16-tools
        sudo zypper -n install texinfo
        sudo zypper -n install zlib-devel
        sudo zypper -n install libndctl-devel
        sudo zypper -n install binutils-devel
        sudo zypper -n install xmlto
        sudo zypper -n install libelf-devel
        sudo zypper -n install pkg-config
        sudo zypper -n install pcre2-devel
        sudo zypper -n install fuse3
        sudo zypper -n install fuse3-devel
        sudo zypper -n install hdf5-devel
        sudo zypper -n install libjpeg-turbo
        sudo zypper -n install libjpeg62-devel
        sudo zypper -n install mpg123
        sudo zypper -n install libarchive-devel
        sudo zypper -n install libSDL2-devel SDL2_image-devel SDL2_ttf-devel

        install_onnxruntime_prebuilt || exit 1
    	CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    # Arch family
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --needed --noconfirm gcc python python-pip || exit 1
        sudo pacman -Sqy make --noconfirm
        sudo pacman -Sqy curl --noconfirm
	sudo pacman -Sqy cmake --noconfirm
        sudo pacman -Sqy git --noconfirm
        sudo pacman -Sqy openssl --noconfirm
        sudo pacman -Sqy bzip2 --noconfirm
        sudo pacman -Sqy zstd --noconfirm
        sudo pacman -Sqy readline --noconfirm
        sudo pacman -Sqy sqlite --noconfirm
        sudo pacman -Sqy libffi --noconfirm
        sudo pacman -Sqy ncurses --noconfirm
        sudo pacman -Sqy xz --noconfirm
        sudo pacman -Sqy lzlib --noconfirm
        sudo pacman -Sqy tk --noconfirm
        sudo pacman -Sqy automake --noconfirm
        sudo pacman -Sqy autoconf --noconfirm
        sudo pacman -Sqy gettext --noconfirm
        sudo pacman -Sqy nasm --noconfirm
        sudo pacman -Sqy libpng --noconfirm
        sudo pacman -Sqy texinfo --noconfirm
        sudo pacman -Sqy zlib --noconfirm
        sudo pacman -Sqy ndctl --noconfirm
        sudo pacman -Sqy binutils --noconfirm
        sudo pacman -Sqy xmlto --noconfirm
        sudo pacman -Sqy libelf --noconfirm
        sudo pacman -Sqy pkgconf --noconfirm
        sudo pacman -Sqy pcre2 --noconfirm
        sudo pacman -Sqy fuse3 --noconfirm
        sudo pacman -Sqy hdf5-openmpi --noconfirm
        sudo pacman -Sqy util-linux --noconfirm
        sudo pacman -Sqy util-linux-libs --noconfirm
        sudo pacman -Sqy libjpeg-turbo --noconfirm
        sudo pacman -Sqy libjpeg6-turbo --noconfirm
        sudo pacman -Sqy mpg123 --noconfirm
        sudo pacman -Sqy libarchive --noconfirm
        sudo pacman -Sqy sdl2 --noconfirm
        sudo pacman -Sqy sdl2_image --noconfirm
        sudo pacman -Sqy sdl2_ttf --noconfirm

        install_onnxruntime_prebuilt || exit 1
    	CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"
    else
        echo -e "\033[31m";
        echo "It seems like your distribution is not supported at this time."
        echo "Currently scalpel3 supports the apt, dnf, zypper, and pacman"
        echo "package managers."
        echo -e "\033[36m"
        exit 1
    fi

    verify_fuse3_development_files || exit 1

    fix_debug_info() {
	echo " " > /dev/null
    }

    g++ -std=c++17 -fPIC -c "$CURDIR/src/pocketfft_mdct.cpp" -o "$CURDIR/src/pocketfft_mdct.o"
    g++ -shared -o "$CURDIR/src/libpocketfft_mdct.so" "$CURDIR/src/pocketfft_mdct.o"
    echo "Built libpocketfft_mdct.so for Linux"

    sudo cp "./src/libpocketfft_mdct.so" "/usr/local/lib"
    sudo ldconfig

    fix_platform_make() {
	cp src/Makefile.am.linux src/Makefile.am
    }
else
    echo "scalpel3 is supported only on macOS and Linux."
    exit 0
fi

CURDIR=`pwd`
GUESSLANG="$CURDIR/src/guesslang"
fix_platform_make &&
    autoreconf -fi && aclocal && automake --gnu --add-missing && autoconf &&
    cd "$CURDIR/src" &&
    rm -rf zlib-ng &&
    git clone https://github.com/zlib-ng/zlib-ng.git &&
    cd zlib-ng &&
    unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH &&
    CPPFLAGS="-I$PWD" ./configure --zlib-compat &&
    make clean &&
    make libz.a &&
    CPPFLAGS="-I$CURDIR/src/zlib-ng $CPPFLAGS" &&
    LDFLAGS="-L$CURDIR/src/zlib-ng $LDFLAGS" &&
    cd "$CURDIR/src" &&
    rm -rf simde &&
    git clone https://github.com/simd-everywhere/simde.git &&
    rm -rf libbacktrace &&
    git clone https://github.com/ianlancetaylor/libbacktrace.git &&
    cd libbacktrace &&
    ./configure &&
    make &&
    sudo make install &&
    cd "$CURDIR" &&
    # Final safety: prevent poison env vars from overriding search paths
    # unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH \
    #     LIBRARY_PATH LD_LIBRARY_PATH DYLD_LIBRARY_PATH &&
    # Ensure /usr/local gets searched first (libbacktrace + other locally-installed things)
    CPPFLAGS="${ONNX_INCLUDE_FIRST}-I/usr/local/include $CPPFLAGS" \
    LDFLAGS="${ONNX_LIB_FIRST}-L/usr/local/lib $LDFLAGS -Wl,-rpath,/usr/local/lib" \
    LIBS="$LIBS" \
    ./configure "${SCALPEL3_ONNX_CONFIGURE_ARGS[@]}" &&
    cd "$CURDIR" &&
    make clean &&
    make &&
    cd "$CURDIR/man" &&
    sudo make install &&
    cd "$CURDIR/src" &&
    fix_debug_info &&

{   echo
    echo -e '\033[34m';
    echo "scalpel3 is now installed."
    if [ "${SCALPEL3_ONNX_PROVIDER:-}" = "cpu" ]; then
        echo "GPU ACCELERATION IS OFF. Run Scalpel3 and TESTS/cmdline.test with -Y cpu."
        echo "See the ONNX diagnostics above for GPU installation instructions."
    fi

    if [ "$SCALPEL3_HOME" == "" ]; then
        echo 'Before running Scalpel, ensure that SCALPEL3_HOME is set to the location of the root scalpel3'
        echo 'directory. To do this, add the following line to your shell startup file (~/.bashrc, ~/.zshrc,'
        echo 'etc.):'
        echo
        echo "  export SCALPEL3_HOME=\"$CURDIR\""
        echo
        echo 'Then reload your shell (e.g., by running source ~/.bashrc) for the changes to take effect.'
        echo 'This only needs to be done once for a given system.'
    fi

    if [ "$(uname)" = "Darwin" ]; then
        echo
        echo -e '\033[33m'
        echo "WARNING: blockmapfs requires macFUSE. Download and install it from:"
        echo
        echo "           https://macfuse.github.io/"
        echo
        echo "         Follow the macFUSE installation and approval instructions. If FUSE 3"
        echo "         development files were unavailable during this build, blockmapfs was"
        echo "         skipped; rerun this script after installing macFUSE to build it."
        echo "         Scalpel3 and the rest of the toolchain do not require macFUSE."
    fi
    echo -e '\033[0m';
    }
