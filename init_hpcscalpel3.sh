#!/bin/bash
#
# Build script for scalpel3 on HPC clusters with MPI and SLURM.
# Optimized for Red Hat Enterprise Linux environments.
#
# Designed for use on scientific computing clusters where:
# - RHEL/CentOS is the base OS
# - An MPI compiler wrapper is available via modules
# - SLURM is the job scheduler
# - User does not have sudo access
# - Dependencies may need to be loaded via module system
#
# Usage: ./init_hpcscalpel3.sh [install_prefix]
# where install_prefix defaults to $HOME/.local if not specified
#
# Written for scalpel3, 2026

set -e  # Exit on error

# Configuration
ONNXRUNTIME_VERSION="1.23.2"
INSTALL_PREFIX="${1:-$HOME/.local}"
ONNXRUNTIME_INSTALL_PREFIX="${INSTALL_PREFIX}"
# record original working directory so we can return after building dependencies
ORIG_DIR="$(pwd)"

echo "=========================================="
echo "scalpel3 HPC Build Script"
echo "=========================================="
echo "Installation prefix: $INSTALL_PREFIX"
echo "ONNX Runtime version: $ONNXRUNTIME_VERSION"
echo ""

# Create installation directories
mkdir -p "$INSTALL_PREFIX/bin"
mkdir -p "$INSTALL_PREFIX/lib"
mkdir -p "$INSTALL_PREFIX/include"
mkdir -p "$INSTALL_PREFIX/share"

# Architecture check
[[ `uname -m` =~ "64" ]] ||
    {
        echo "scalpel3 works only on 64-bit platforms."
        exit 1
    }

# Verify we're on Linux
if [ "$(uname)" != "Linux" ]; then
    echo "scalpel3 on HPC clusters is supported only on Linux."
    exit 1
fi

source /etc/os-release

# Check for RHEL/CentOS family
if ! ([[ "$ID" == "rhel" ]] || [[ "$ID" == "centos" ]] || [[ "$ID_LIKE" == "rhel"* ]] || [[ "$ID_LIKE" == "fedora"* ]]); then
    echo "WARNING: This script is optimized for RHEL/CentOS."
    echo "Your distribution is: $ID"
    echo "Some steps may fail. Continuing anyway..."
fi

echo "Detected OS: $ID ($VERSION_ID)"
echo ""

# Function to load a module; returns 0 on success, 1 if not available
load_or_install_module() {
    local module_name=$1
    local package_name=$2
    
    echo "Checking for $module_name..."
    if module avail "$module_name" &>/dev/null; then
        echo "  Loading module: $module_name"
        module load "$module_name" 2>/dev/null && return 0 || return 1
    else
        echo "  Module not available; skipping."
        return 1
    fi
}

# Load common HPC modules
echo "Loading HPC environment modules..."
module purge 2>/dev/null || true
load_or_install_module "gcc" "GCC"
# Try Intel compiler + MPI (versioned first, then bare name, then openmpi fallback)
if module avail "intel/2021.5.0" &>/dev/null; then
    module load intel/2021.5.0 2>/dev/null || true
fi
if ! load_or_install_module "intel-mpi/2021.5.1" "Intel MPI"; then
    if ! load_or_install_module "intel-mpi" "Intel MPI"; then
        load_or_install_module "intelmpi" "Intel MPI"
        load_or_install_module "openmpi" "OpenMPI"
    fi
fi

echo ""
echo "=========================================="
echo "Installing Build Dependencies"
echo "=========================================="
echo ""

# Check for mandatory commands
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "ERROR: $1 is required but not installed."
        echo "Please ensure $2 is installed or loaded via modules."
        exit 1
    fi
}

echo "Checking for required build tools..."
check_command "gcc" "gcc"
check_command "g++" "g++"
check_command "make" "make"
check_command "git" "git"
check_command "curl" "curl"
check_command "mpicc" "an MPI compiler wrapper (Intel MPI or OpenMPI)"

echo "All required tools found."
echo "Using host compiler: $(command -v gcc)"
echo "Using MPI compiler wrapper: $(command -v mpicc)"
echo ""

# ONNX Runtime installation for HPC
install_onnxruntime_prebuilt() {
    echo "=========================================="
    echo "Installing ONNX Runtime"
    echo "=========================================="
    
    # Check if already installed
    if [ -f "$ONNXRUNTIME_INSTALL_PREFIX/include/onnxruntime_cxx_api.h" ] || \
       [ -f "$ONNXRUNTIME_INSTALL_PREFIX/include/onnxruntime_c_api.h" ]; then
        echo "ONNX Runtime headers already present; skipping install."
        return 0
    fi

    local arch pkg url tmpdir root
    arch="$(uname -m)"

    case "$arch" in
        x86_64|amd64)  pkg="onnxruntime-linux-x64-${ONNXRUNTIME_VERSION}.tgz" ;;
        aarch64)       pkg="onnxruntime-linux-aarch64-${ONNXRUNTIME_VERSION}.tgz" ;;
        *)
            echo "ERROR: Unsupported architecture for ONNX Runtime: $arch"
            return 1
            ;;
    esac

    url="https://sourceforge.net/projects/onnx-runtime.mirror/files/v${ONNXRUNTIME_VERSION}/${pkg}/download"
    tmpdir="$(mktemp -d -t onnxrt.XXXXXX)"

    echo "Downloading ONNX Runtime ${ONNXRUNTIME_VERSION}..."
    curl -L "$url" -o "$tmpdir/$pkg" || {
        echo "ERROR: Failed to download ONNX Runtime"
        rm -rf "$tmpdir"
        return 1
    }

    echo "Extracting ONNX Runtime..."
    tar -xzf "$tmpdir/$pkg" -C "$tmpdir" || {
        echo "ERROR: Failed to extract ONNX Runtime"
        rm -rf "$tmpdir"
        return 1
    }

    root="$(find "$tmpdir" -maxdepth 1 -type d -name "onnxruntime-*" | head -n 1)"
    if [ -z "$root" ]; then
        echo "ERROR: Failed to locate extracted ONNX Runtime directory."
        rm -rf "$tmpdir"
        return 1
    fi

    echo "Installing ONNX Runtime headers to ${ONNXRUNTIME_INSTALL_PREFIX}/include/"
    cp -R "$root/include/"* "${ONNXRUNTIME_INSTALL_PREFIX}/include/"

    echo "Installing ONNX Runtime libs to ${ONNXRUNTIME_INSTALL_PREFIX}/lib/"
    cp -f "$root/lib/"libonnxruntime* "${ONNXRUNTIME_INSTALL_PREFIX}/lib/" 2>/dev/null || true

    # Set library path
    export LD_LIBRARY_PATH="${ONNXRUNTIME_INSTALL_PREFIX}/lib:${LD_LIBRARY_PATH}"

    rm -rf "$tmpdir"
    echo "ONNX Runtime installation complete."
    echo ""
}

# Install ONNX Runtime
install_onnxruntime_prebuilt

# Install xmlto if not available
install_xmlto() {
    echo "=========================================="
    echo "Checking/Installing xmlto"
    echo "=========================================="
    
    # Check if xmlto already exists
    if command -v xmlto &> /dev/null; then
        echo "xmlto is already installed."
        return 0
    fi
    
    echo "xmlto not found; building from source..."
    
    local tmpdir pkg_url tmpdir root
    tmpdir="$(mktemp -d -t xmlto.XXXXXX)"
    prev_pwd="$(pwd)"
    trap 'cd "$prev_pwd" >/dev/null 2>&1 || true; rm -rf "$tmpdir" >/dev/null 2>&1 || true' RETURN
    
    # Download xmlto source
    echo "Downloading xmlto..."
    curl -L "https://pagure.io/xmlto/archive/0.0.29/xmlto-0.0.29.tar.gz" \
        -o "$tmpdir/xmlto-0.0.29.tar.gz" || {
        echo "ERROR: Failed to download xmlto"
        rm -rf "$tmpdir"
        return 1
    }
    
    echo "Extracting xmlto..."
    cd "$tmpdir"
    tar -xzf xmlto-0.0.29.tar.gz || {
        echo "ERROR: Failed to extract xmlto"
        rm -rf "$tmpdir"
        return 1
    }
    
    cd xmlto-0.0.29 || return 1

    # Ensure autotools support files/dirs exist so automake can run
    mkdir -p m4 build-aux
    if [ ! -f README ]; then
        echo "xmlto" > README
    fi
    # automake requires NEWS and AUTHORS; create minimal files if missing
    if [ ! -f AUTHORS ]; then
        echo "Unknown" > AUTHORS
    fi
    if [ ! -f NEWS ]; then
        echo "Initial release." > NEWS
    fi

    # If xmlif needs updating (per install instructions), run flex to produce xmlif.c
    if [ -f xmlif/xmlif.l ] && [ ! -f xmlif/xmlif.c ]; then
        echo "xmlif lexical file found; generating xmlif.c via flex..."
        if command -v flex &>/dev/null; then
            flex -o xmlif/xmlif.c xmlif/xmlif.l || {
                echo "ERROR: flex failed to generate xmlif.c"
                rm -rf "$tmpdir"
                return 1
            }
        else
            echo "flex not found. Attempting to build flex locally..."
            FLEX_TMP="$(mktemp -d -t flex.XXXXXX)"
            (cd "$FLEX_TMP" && \
                curl -L -o flex.tar.gz https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz && \
                tar -xzf flex.tar.gz && cd flex-2.6.4 && ./configure --prefix="$INSTALL_PREFIX" && make -j"$(nproc)" && make install) || {
                echo "WARNING: failed to build flex locally. Please install flex or load it as a module."
                rm -rf "$FLEX_TMP" "$tmpdir"
                return 1
            }
            rm -rf "$FLEX_TMP"
            # Retry generating xmlif.c with the newly installed flex
            PATH="$INSTALL_PREFIX/bin:$PATH" flex -o xmlif/xmlif.c xmlif/xmlif.l || {
                echo "ERROR: flex failed even after local build."
                rm -rf "$tmpdir"
                return 1
            }
        fi
    fi

    # If a configure script is not provided, generate the autotools files
    if [ ! -x ./configure ]; then
        echo "No configure script found; generating autotools files (autoreconf/automake)..."
        if command -v autoreconf &>/dev/null; then
            autoreconf -fi || true
        else
            # Try to run the automake chain directly if autoreconf missing
            aclocal || true
            automake --gnu --add-missing || true
            autoconf || true
        fi
    fi

    # Verify configure exists now
    if [ ! -x ./configure ]; then
        echo "ERROR: configure was not produced. Ensure autoconf/automake are installed."
        rm -rf "$tmpdir"
        return 1
    fi

    echo "Configuring xmlto..."
    ./configure --prefix="$INSTALL_PREFIX" || {
        echo "WARNING: xmlto configure failed. Trying with alternative flags..."
        ./configure --prefix="$INSTALL_PREFIX" --disable-nls || {
            echo "ERROR: xmlto configuration failed"
            rm -rf "$tmpdir"
            return 1
        }
    }

    echo "Building xmlto..."
    make || {
        echo "ERROR: xmlto build failed"
        rm -rf "$tmpdir"
        return 1
    }
    
    echo "Installing xmlto..."
    make install || {
        echo "ERROR: xmlto install failed"
        rm -rf "$tmpdir"
        return 1
    }
    
    rm -rf "$tmpdir"
    
    # Update PATH to include xmlto
    export PATH="${INSTALL_PREFIX}/bin:${PATH}"
    
    echo "xmlto successfully installed to ${INSTALL_PREFIX}/bin/xmlto"
    echo ""
}

# Install xmlto
install_xmlto

# Install libjpeg-turbo if not available
install_libjpeg_turbo() {
    echo "=========================================="
    echo "Checking/Installing libjpeg-turbo"
    echo "=========================================="

    # If already installed into prefix, skip
    if [ -f "${INSTALL_PREFIX}/lib/libturbojpeg.so" ] || [ -f "${INSTALL_PREFIX}/lib/libjpeg.so" ] || \
       [ -f "${INSTALL_PREFIX}/lib64/libturbojpeg.so" ] || [ -f "${INSTALL_PREFIX}/lib64/libjpeg.so" ]; then
        echo "libjpeg-turbo appears to be installed in ${INSTALL_PREFIX}; skipping."
        return 0
    fi

    local tmpdir pkg url root cmake_cmd
    tmpdir="$(mktemp -d -t libjpeg.XXXXXX)"
    trap 'rm -rf "$tmpdir" >/dev/null 2>&1 || true' RETURN

    url="https://github.com/libjpeg-turbo/libjpeg-turbo/releases/download/3.1.3/libjpeg-turbo-3.1.3.tar.gz"

    echo "Downloading libjpeg-turbo..."
    curl -L "$url" -o "$tmpdir/libjpeg-turbo-3.1.3.tar.gz" || {
        echo "ERROR: Failed to download libjpeg-turbo"
        return 1
    }

    echo "Extracting libjpeg-turbo..."
    cd "$tmpdir" || return 1
    tar -xzf libjpeg-turbo-3.1.3.tar.gz || { echo "ERROR: failed to extract"; return 1; }
    cd libjpeg-turbo-3.1.3 || return 1

    # Ensure cmake is available
    if command -v cmake &>/dev/null; then
        cmake_cmd=cmake
    elif command -v cmake3 &>/dev/null; then
        cmake_cmd=cmake3
    else
        echo "ERROR: cmake is required to build libjpeg-turbo but was not found in PATH."
        echo "Please install cmake or load a module that provides it, then re-run this script."
        return 1
    fi

    # Warn if assembler not found (NASM/YASM) — build will still proceed but without SIMD
    if ! command -v nasm &>/dev/null && ! command -v yasm &>/dev/null; then
        echo "WARNING: NASM/YASM not found. Build will proceed but SIMD optimizations will be disabled."
    else
        echo "Assembler found; SIMD-enabled build may be possible."
    fi

    echo "Configuring libjpeg-turbo (out-of-tree build)..."
    mkdir -p build && cd build || return 1
    "$cmake_cmd" -G"Unix Makefiles" -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" -DCMAKE_BUILD_TYPE=Release .. || {
        echo "ERROR: cmake configuration failed for libjpeg-turbo"
        return 1
    }

    echo "Building libjpeg-turbo..."
    make -j "$(nproc)" || { echo "ERROR: make failed for libjpeg-turbo"; return 1; }

    echo "Installing libjpeg-turbo to $INSTALL_PREFIX..."
    make install || { echo "ERROR: make install failed for libjpeg-turbo"; return 1; }

    # Ensure libs are discoverable; handle both lib and lib64
    local lib_path lib64_path
    [ -d "$INSTALL_PREFIX/lib" ] && lib_path="$INSTALL_PREFIX/lib" || lib_path=""
    [ -d "$INSTALL_PREFIX/lib64" ] && lib64_path="$INSTALL_PREFIX/lib64" || lib64_path=""
    
    if [ -n "$lib64_path" ]; then
        export LD_LIBRARY_PATH="$lib64_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib64_path/pkgconfig:$PKG_CONFIG_PATH"
    fi
    if [ -n "$lib_path" ]; then
        export LD_LIBRARY_PATH="$lib_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib_path/pkgconfig:$PKG_CONFIG_PATH"
    fi

    # Copy/symlink libraries from lib64 to lib if lib64 was used (for compatibility)
    if [ -d "$INSTALL_PREFIX/lib64" ] && [ ! -d "$INSTALL_PREFIX/lib" ]; then
        mkdir -p "$INSTALL_PREFIX/lib"
        ln -sf ../lib64/* "$INSTALL_PREFIX/lib/" 2>/dev/null || true
    fi

    # Ensure libjpeg.so exists (some configure scripts look for -ljpeg)
    for libdir in "$INSTALL_PREFIX/lib" "$INSTALL_PREFIX/lib64"; do
        if [ -d "$libdir" ]; then
            if [ ! -f "$libdir/libjpeg.so" ] && [ -f "$libdir/libturbojpeg.so" ]; then
                ln -sf libturbojpeg.so "$libdir/libjpeg.so"
            fi
        fi
    done

    echo "libjpeg-turbo installed to $INSTALL_PREFIX"
}

# Install libjpeg-turbo
install_libjpeg_turbo

# Install giflib if not available
: <<'DISABLED_INSTALL_GIFLIB'
install_giflib() {
    echo "=========================================="
    echo "Checking/Installing giflib"
    echo "=========================================="

    # Check if already installed
    if [ -f "${INSTALL_PREFIX}/lib/libgif.so" ] || [ -f "${INSTALL_PREFIX}/lib64/libgif.so" ]; then
        echo "giflib appears to be installed in ${INSTALL_PREFIX}; skipping."
        return 0
    fi

    local tmpdir url
    tmpdir="$(mktemp -d -t giflib.XXXXXX)"
    trap 'rm -rf "$tmpdir" >/dev/null 2>&1 || true' RETURN

    url="https://phoenixnap.dl.sourceforge.net/project/giflib/giflib-5.2.2.tar.gz"

    echo "Downloading giflib..."
    curl -L "$url" -o "$tmpdir/giflib-5.2.2.tar.gz" || {
        echo "ERROR: Failed to download giflib"
        return 1
    }

    echo "Extracting giflib..."
    cd "$tmpdir" || return 1
    tar -xzf giflib-5.2.2.tar.gz || { echo "ERROR: failed to extract giflib"; return 1; }
    cd giflib-5.2.2 || return 1

    if ! command -v convert &>/dev/null; then
        echo "WARNING: 'convert' not found; disabling documentation build in Makefile."
        sed -i 's/^[[:space:]]*\$(MAKE) -C doc/#&/' Makefile
    fi

    echo "Building giflib"
    make -j "$(nproc)" PREFIX="$INSTALL_PREFIX" || { echo "ERROR: make failed for giflib"; return 1; }

    echo "Installing giflib to $INSTALL_PREFIX..."
    make install PREFIX="$INSTALL_PREFIX" || { echo "ERROR: make install failed for giflib"; return 1; }
}

install_giflib
DISABLED_INSTALL_GIFLIB

# Install SDL2 development stack if not available
install_sdl2_devel_stack() {
    echo "=========================================="
    echo "Checking/Installing libSDL2-devel stack"
    echo "=========================================="

    local lib_path lib64_path
    [ -d "$INSTALL_PREFIX/lib" ] && lib_path="$INSTALL_PREFIX/lib" || lib_path=""
    [ -d "$INSTALL_PREFIX/lib64" ] && lib64_path="$INSTALL_PREFIX/lib64" || lib64_path=""

    if [ -n "$lib64_path" ]; then
        export LD_LIBRARY_PATH="$lib64_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib64_path/pkgconfig:$PKG_CONFIG_PATH"
    fi
    if [ -n "$lib_path" ]; then
        export LD_LIBRARY_PATH="$lib_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib_path/pkgconfig:$PKG_CONFIG_PATH"
    fi

    if pkg-config --exists sdl2 && pkg-config --exists SDL2_image && pkg-config --exists SDL2_ttf; then
        echo "libSDL2-devel, SDL2_image-devel, and SDL2_ttf-devel appear available; skipping."
        return 0
    fi

    local tmpdir
    tmpdir="$(mktemp -d -t sdl2deps.XXXXXX)"
    trap 'rm -rf "$tmpdir" >/dev/null 2>&1 || true' RETURN

    install_one_sdl_pkg() {
        local module_name="$1"
        local pkg_name="$2"
        local pkg_version="$3"
        local pkg_url="$4"
        local configure_extra="$5"

        if pkg-config --exists "$module_name"; then
            echo "$pkg_name already detected via pkg-config; skipping."
            return 0
        fi

        echo "Downloading $pkg_name..."
        curl -L "$pkg_url" -o "$tmpdir/${pkg_name}-${pkg_version}.tar.gz" || {
            echo "ERROR: Failed to download $pkg_name"
            return 1
        }

        echo "Extracting $pkg_name..."
        cd "$tmpdir" || return 1
        tar -xzf "${pkg_name}-${pkg_version}.tar.gz" || {
            echo "ERROR: Failed to extract $pkg_name"
            return 1
        }

        cd "${pkg_name}-${pkg_version}" || return 1

        echo "Configuring $pkg_name..."
        CPPFLAGS="-I${INSTALL_PREFIX}/include ${CPPFLAGS}" \
        LDFLAGS="-L${INSTALL_PREFIX}/lib -L${INSTALL_PREFIX}/lib64 ${LDFLAGS}" \
        ./configure --prefix="$INSTALL_PREFIX" $configure_extra || {
            echo "ERROR: $pkg_name configuration failed"
            return 1
        }

        echo "Building $pkg_name..."
        make -j "$(nproc)" || {
            echo "ERROR: $pkg_name build failed"
            return 1
        }

        echo "Installing $pkg_name..."
        make install || {
            echo "ERROR: $pkg_name install failed"
            return 1
        }
    }

    install_one_sdl_pkg "sdl2" "SDL2" "2.30.10" \
        "https://github.com/libsdl-org/SDL/releases/download/release-2.30.10/SDL2-2.30.10.tar.gz" ""

    install_one_sdl_pkg "SDL2_image" "SDL2_image" "2.8.8" \
        "https://github.com/libsdl-org/SDL_image/releases/download/release-2.8.8/SDL2_image-2.8.8.tar.gz" ""

    install_one_sdl_pkg "SDL2_ttf" "SDL2_ttf" "2.24.0" \
        "https://github.com/libsdl-org/SDL_ttf/releases/download/release-2.24.0/SDL2_ttf-2.24.0.tar.gz" ""

    # Refresh paths after install so downstream configure picks them up.
    [ -d "$INSTALL_PREFIX/lib" ] && export LD_LIBRARY_PATH="$INSTALL_PREFIX/lib:$LD_LIBRARY_PATH"
    [ -d "$INSTALL_PREFIX/lib64" ] && export LD_LIBRARY_PATH="$INSTALL_PREFIX/lib64:$LD_LIBRARY_PATH"
    [ -d "$INSTALL_PREFIX/lib/pkgconfig" ] && export PKG_CONFIG_PATH="$INSTALL_PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
    [ -d "$INSTALL_PREFIX/lib64/pkgconfig" ] && export PKG_CONFIG_PATH="$INSTALL_PREFIX/lib64/pkgconfig:$PKG_CONFIG_PATH"

    echo "libSDL2-devel stack installed to $INSTALL_PREFIX"
}

# Install SDL2 development packages (libSDL2-devel, SDL2_image-devel, SDL2_ttf-devel equivalents)
install_sdl2_devel_stack

# Install mpg123 if not available
install_mpg123() {
    echo "=========================================="
    echo "Checking/Installing mpg123"
    echo "=========================================="

    # Check if already installed
    if [ -f "${INSTALL_PREFIX}/lib/libmpg123.so" ] || [ -f "${INSTALL_PREFIX}/lib64/libmpg123.so" ]; then
        echo "mpg123 appears to be installed in ${INSTALL_PREFIX}; skipping."
        return 0
    fi

    local tmpdir url
    tmpdir="$(mktemp -d -t mpg123.XXXXXX)"
    trap 'rm -rf "$tmpdir" >/dev/null 2>&1 || true' RETURN

    url="https://cfhcable.dl.sourceforge.net/project/mpg123/mpg123/1.33.4/mpg123-1.33.4.tar.bz2"

    echo "Downloading mpg123..."
    curl -L "$url" -o "$tmpdir/mpg123-1.33.4.tar.bz2" || {
        echo "ERROR: Failed to download mpg123"
        return 1
    }

    echo "Extracting mpg123..."
    cd "$tmpdir" || return 1
    tar -xjf mpg123-1.33.4.tar.bz2 || { echo "ERROR: failed to extract mpg123"; return 1; }
    cd mpg123-1.33.4 || return 1

    echo "Configuring mpg123..."
    ./configure --prefix="$INSTALL_PREFIX" --with-audio=dummy || {
        echo "ERROR: mpg123 configuration failed"
        return 1
    }

    echo "Building mpg123..."
    make -j "$(nproc)" || { echo "ERROR: make failed for mpg123"; return 1; }

    echo "Installing mpg123 to $INSTALL_PREFIX..."
    make install || { echo "ERROR: make install failed for mpg123"; return 1; }

    # Ensure libs are discoverable; handle both lib and lib64
    local lib_path lib64_path
    [ -d "$INSTALL_PREFIX/lib" ] && lib_path="$INSTALL_PREFIX/lib" || lib_path=""
    [ -d "$INSTALL_PREFIX/lib64" ] && lib64_path="$INSTALL_PREFIX/lib64" || lib64_path=""
    
    if [ -n "$lib64_path" ]; then
        export LD_LIBRARY_PATH="$lib64_path:$LD_LIBRARY_PATH"
    fi
    if [ -n "$lib_path" ]; then
        export LD_LIBRARY_PATH="$lib_path:$LD_LIBRARY_PATH"
    fi

    echo "mpg123 installed to $INSTALL_PREFIX"
}

# Install mpg123
install_mpg123

# Install libarchive if not available
install_libarchive() {
    echo "=========================================="
    echo "Checking/Installing libarchive"
    echo "=========================================="

    # Check if already installed
    if [ -f "${INSTALL_PREFIX}/lib/libarchive.so" ] || [ -f "${INSTALL_PREFIX}/lib64/libarchive.so" ]; then
        echo "libarchive appears to be installed in ${INSTALL_PREFIX}; skipping."
        return 0
    fi

    local tmpdir url
    tmpdir="$(mktemp -d -t libarchive.XXXXXX)"
    trap 'rm -rf "$tmpdir" >/dev/null 2>&1 || true' RETURN

    url="https://github.com/libarchive/libarchive/releases/download/v3.7.2/libarchive-3.7.2.tar.gz"

    echo "Downloading libarchive..."
    curl -L "$url" -o "$tmpdir/libarchive-3.7.2.tar.gz" || {
        echo "ERROR: Failed to download libarchive"
        return 1
    }

    echo "Extracting libarchive..."
    cd "$tmpdir" || return 1
    tar -xzf libarchive-3.7.2.tar.gz || { echo "ERROR: failed to extract libarchive"; return 1; }
    cd libarchive-3.7.2 || return 1

    echo "Configuring libarchive..."
    ./configure --prefix="$INSTALL_PREFIX" || {
        echo "ERROR: libarchive configuration failed"
        return 1
    }

    echo "Building libarchive..."
    make -j "$(nproc)" || { echo "ERROR: make failed for libarchive"; return 1; }

    echo "Installing libarchive to $INSTALL_PREFIX..."
    make install || { echo "ERROR: make install failed for libarchive"; return 1; }

    # Ensure libs are discoverable; handle both lib and lib64
    local lib_path lib64_path
    [ -d "$INSTALL_PREFIX/lib" ] && lib_path="$INSTALL_PREFIX/lib" || lib_path=""
    [ -d "$INSTALL_PREFIX/lib64" ] && lib64_path="$INSTALL_PREFIX/lib64" || lib64_path=""
    
    if [ -n "$lib64_path" ]; then
        export LD_LIBRARY_PATH="$lib64_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib64_path/pkgconfig:$PKG_CONFIG_PATH"
    fi
    if [ -n "$lib_path" ]; then
        export LD_LIBRARY_PATH="$lib_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib_path/pkgconfig:$PKG_CONFIG_PATH"
    fi

    echo "libarchive installed to $INSTALL_PREFIX"
}

# Install libarchive
install_libarchive

# Install fuse2 if not available
install_fuse2() {
    echo "=========================================="
    echo "Checking/Installing fuse2"
    echo "=========================================="

    # Check if already installed
    if [ -f "${INSTALL_PREFIX}/lib/libfuse.so" ] || [ -f "${INSTALL_PREFIX}/lib64/libfuse.so" ]; then
        echo "fuse2 appears to be installed in ${INSTALL_PREFIX}; skipping."
        # even though we aren't rebuilding, the later configure/make steps
        # rely on pkg-config and LD_LIBRARY_PATH to find the library.  the
        # code in the main install path exported those values, so we need to
        # do the same when skipping so a second run behaves the same as the
        # first one.
        local lib_path lib64_path
        [ -d "$INSTALL_PREFIX/lib" ] && lib_path="$INSTALL_PREFIX/lib" || lib_path=""
        [ -d "$INSTALL_PREFIX/lib64" ] && lib64_path="$INSTALL_PREFIX/lib64" || lib64_path=""
        if [ -n "$lib64_path" ]; then
            export LD_LIBRARY_PATH="$lib64_path:$LD_LIBRARY_PATH"
            export PKG_CONFIG_PATH="$lib64_path/pkgconfig:$PKG_CONFIG_PATH"
        fi
        if [ -n "$lib_path" ]; then
            export LD_LIBRARY_PATH="$lib_path:$LD_LIBRARY_PATH"
            export PKG_CONFIG_PATH="$lib_path/pkgconfig:$PKG_CONFIG_PATH"
        fi
        return 0
    fi

    local tmpdir url
    tmpdir="$(mktemp -d -t fuse2.XXXXXX)"
    trap 'rm -rf "$tmpdir" >/dev/null 2>&1 || true' RETURN

    url="https://github.com/libfuse/libfuse/releases/download/fuse-2.9.9/fuse-2.9.9.tar.gz"

    echo "Downloading fuse2..."
    curl -L "$url" -o "$tmpdir/fuse-2.9.9.tar.gz" || {
        echo "ERROR: Failed to download fuse2"
        return 1
    }

    echo "Extracting fuse2..."
    cd "$tmpdir" || return 1
    tar -xzf fuse-2.9.9.tar.gz || { echo "ERROR: failed to extract fuse2"; return 1; }
    cd fuse-2.9.9 || return 1

    echo "Configuring fuse2..."
    ./configure --prefix="$INSTALL_PREFIX" --disable-util || {
        echo "ERROR: fuse2 configuration failed"
        return 1
    }

    echo "Building fuse2..."
    make -j "$(nproc)" || { echo "ERROR: make failed for fuse2"; return 1; }

    echo "Installing fuse2 to $INSTALL_PREFIX..."
    make install || { echo "ERROR: make install failed for fuse2"; return 1; }

    # Ensure libs are discoverable; handle both lib and lib64
    local lib_path lib64_path
    [ -d "$INSTALL_PREFIX/lib" ] && lib_path="$INSTALL_PREFIX/lib" || lib_path=""
    [ -d "$INSTALL_PREFIX/lib64" ] && lib64_path="$INSTALL_PREFIX/lib64" || lib64_path=""
    
    if [ -n "$lib64_path" ]; then
        export LD_LIBRARY_PATH="$lib64_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib64_path/pkgconfig:$PKG_CONFIG_PATH"
    fi
    if [ -n "$lib_path" ]; then
        export LD_LIBRARY_PATH="$lib_path:$LD_LIBRARY_PATH"
        export PKG_CONFIG_PATH="$lib_path/pkgconfig:$PKG_CONFIG_PATH"
    fi

    echo "fuse2 installed to $INSTALL_PREFIX"
}

# Install fuse2
install_fuse2

# Set up compile flags
HOST_CC="$(command -v gcc)"
MPI_CC="$(command -v mpicc)"
export CC="$HOST_CC"
export MPICC="$MPI_CC"
CPPFLAGS="-I${INSTALL_PREFIX}/include"
LDFLAGS="-L${INSTALL_PREFIX}/lib"
# Also add lib64 if it exists (RHEL/CentOS 64-bit default)
[ -d "${INSTALL_PREFIX}/lib64" ] && LDFLAGS="-L${INSTALL_PREFIX}/lib64 ${LDFLAGS}"
CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
# Add any lib64 from onnxruntime prefix as well
[ -d "${ONNXRUNTIME_INSTALL_PREFIX}/lib64" ] && LDFLAGS="${LDFLAGS} -L${ONNXRUNTIME_INSTALL_PREFIX}/lib64"

export CPPFLAGS LDFLAGS
export LD_LIBRARY_PATH="${INSTALL_PREFIX}/lib:${INSTALL_PREFIX}/lib64:${ONNXRUNTIME_INSTALL_PREFIX}/lib:${ONNXRUNTIME_INSTALL_PREFIX}/lib64:${LD_LIBRARY_PATH}"
# make sure pkg-config looks inside our install prefix as well; this
# prevents a rerun of the script from losing the path when install_* was
# skipped earlier.
export PKG_CONFIG_PATH="${INSTALL_PREFIX}/lib/pkgconfig:${INSTALL_PREFIX}/lib64/pkgconfig:${PKG_CONFIG_PATH}"

# ensure we're back in the original project directory before building
cd "$ORIG_DIR" || exit 1
CURDIR="$(pwd)"

echo "=========================================="
echo "Building scalpel3"
echo "=========================================="
echo ""

# Fix platform-specific Makefile
echo "Configuring build system for Linux..."
# Use absolute paths to avoid failures if cwd changed by earlier steps
cp "$CURDIR/src/Makefile.am.linux" "$CURDIR/src/Makefile.am"

# Build pocketfft_mdct library
echo "Building pocketfft_mdct library..."
g++ -std=c++17 -fPIC -c "$CURDIR/src/pocketfft_mdct.cpp" -o "$CURDIR/src/pocketfft_mdct.o"
g++ -shared -o "$CURDIR/src/libpocketfft_mdct.so" "$CURDIR/src/pocketfft_mdct.o"
echo "Built libpocketfft_mdct.so for Linux"

# Copy to installation directory
cp "$CURDIR/src/libpocketfft_mdct.so" "${INSTALL_PREFIX}/lib/"
chmod 755 "${INSTALL_PREFIX}/lib/libpocketfft_mdct.so"

echo ""
echo "Running autotools configuration..."

# Create necessary directories and files
mkdir -p m4 build-aux

# Create a minimal README if it doesn't exist (required by automake)
if [ ! -f README ]; then
    echo "scalpel3" > README
fi

# Run autotools
autoreconf -fi && aclocal && automake --gnu --add-missing && autoconf

# Clone and build dependencies
cd "$CURDIR/src" || exit 1

# Clean up old clones
rm -rf zlib-ng 2>/dev/null || true
rm -rf simde 2>/dev/null || true
rm -rf libbacktrace 2>/dev/null || true

echo "Cloning zlib-ng..."
git clone https://github.com/zlib-ng/zlib-ng.git

echo "Building zlib-ng..."
cd zlib-ng || exit 1
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH
CPPFLAGS="-I$PWD" ./configure --zlib-compat
make clean
make libz.a
cd "$CURDIR/src" || exit 1

# Update flags to use local zlib-ng
CPPFLAGS="-I$CURDIR/src/zlib-ng $CPPFLAGS"
LDFLAGS="-L$CURDIR/src/zlib-ng $LDFLAGS"
LIBS="$CURDIR/src/zlib-ng/libz.a $LIBS"

echo "Cloning SIMD Everywhere..."
git clone https://github.com/simd-everywhere/simde.git

echo "Cloning libbacktrace..."
git clone https://github.com/ianlancetaylor/libbacktrace.git

echo "Building libbacktrace..."
cd libbacktrace || exit 1
./configure --prefix="$INSTALL_PREFIX"
make
make install PREFIX="$INSTALL_PREFIX"
cd "$CURDIR" || exit 1

# Run main configure with all flags
echo "Running main scalpel3 configuration..."
CC="$HOST_CC" MPICC="$MPI_CC" CPPFLAGS="$CPPFLAGS" LDFLAGS="$LDFLAGS" LIBS="$LIBS" ./configure \
    --prefix="$INSTALL_PREFIX" \
    2>&1 | tee configure.log

# Build and install scalpel3
echo ""
echo "Building scalpel3..."
make clean
make -j "$(nproc)" 2>&1 | tee build.log

echo ""
echo "Installing scalpel3..."
make install

# Install man pages
if [ -d "$CURDIR/man" ]; then
    echo "Installing man pages..."
    cd "$CURDIR/man" || exit 1
    make install PREFIX="$INSTALL_PREFIX" 2>/dev/null || true
    cd "$CURDIR" || exit 1
fi

echo ""
echo "=========================================="
echo "Installation Complete"
echo "=========================================="
echo ""
echo "scalpel3 has been built and installed to: $INSTALL_PREFIX"
echo ""
echo "To use scalpel3, add the following to your shell startup file"
echo "or execute these commands in your SLURM job script:"
echo ""
echo "  export PATH=\"${INSTALL_PREFIX}/bin:\$PATH\""
echo "  export LD_LIBRARY_PATH=\"${INSTALL_PREFIX}/lib:\$LD_LIBRARY_PATH\""
echo "  export LIBRARY_PATH=\"${INSTALL_PREFIX}/lib:\$LIBRARY_PATH\""
echo "  export CPATH=\"${INSTALL_PREFIX}/include:\$CPATH\""
echo ""
if [ "$INSTALL_PREFIX" != "/usr/local" ]; then
    echo "  export SCALPEL3_HOME=\"$CURDIR\""
    echo ""
fi
echo "To build scalpel3 for parallel execution, ensure the same MPI stack is loaded"
echo "for both build and run time, for example:"
echo "  module load intelmpi"
echo "or"
echo "  module load openmpi"
echo ""
echo "For SLURM job submission, use srun or mpirun with the compiled executables."
echo ""
