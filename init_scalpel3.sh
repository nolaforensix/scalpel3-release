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

# ONNX Runtime (C/C++) - CPU prebuilt install
ONNXRUNTIME_VERSION="1.23.2"
ONNXRUNTIME_INSTALL_PREFIX="/usr/local"
echo "Scalpel's ONNX version: " $ONNXRUNTIME_VERSION

# Returns 0 (true) if an NVIDIA GPU is present and nvidia-smi works
has_nvidia_gpu() {
    command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null
}

install_onnxruntime_prebuilt() {
    local os arch pkg url tmpdir root libdir ver_dylib ver_so use_gpu

    os="$(uname)"
    arch="$(uname -m)"
    libdir="${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    use_gpu=0

    if [ -f "$ONNXRUNTIME_INSTALL_PREFIX/include/onnxruntime_cxx_api.h" ] && \
       [ -f "$ONNXRUNTIME_INSTALL_PREFIX/include/onnxruntime_c_api.h" ] && \
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

        # If GPU is present but CUDA provider lib is missing, fall through to reinstall.
        if has_nvidia_gpu && ! ls "$libdir"/libonnxruntime_providers_cuda* >/dev/null 2>&1; then
            echo "ONNX Runtime headers present but CUDA provider missing. Reinstalling GPU version."
        else
            echo "ONNX Runtime headers already present; skipping install."
            return 0
        fi
    fi

    case "$os" in
        Darwin)
            case "$arch" in
                arm64)  pkg="onnxruntime-osx-arm64-${ONNXRUNTIME_VERSION}.tgz" ;;
                x86_64) pkg="onnxruntime-osx-x86_64-${ONNXRUNTIME_VERSION}.tgz" ;;
                *) echo "Unsupported macOS arch for ONNX Runtime: $arch"; return 1 ;;
            esac
            ;;
        Linux)
            case "$arch" in
                x86_64|amd64)
                    if has_nvidia_gpu; then
                        pkg="onnxruntime-linux-x64-gpu-${ONNXRUNTIME_VERSION}.tgz"
                        use_gpu=1
                        echo "NVIDIA GPU detected, using CUDA-enabled ONNX Runtime."
                    else
                        pkg="onnxruntime-linux-x64-${ONNXRUNTIME_VERSION}.tgz"
                        echo "No NVIDIA GPU detected, using CPU ONNX Runtime."
                    fi
                    ;;
                aarch64|arm64) pkg="onnxruntime-linux-aarch64-${ONNXRUNTIME_VERSION}.tgz" ;;
                *) echo "Unsupported Linux arch for ONNX Runtime: $arch"; return 1 ;;
            esac
            ;;
        *)
            echo "Unsupported OS for ONNX Runtime prebuilt: $os"
            return 1
            ;;
    esac

    if [ "$use_gpu" = "1" ]; then
        url="https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/${pkg}"
    else
        url="https://sourceforge.net/projects/onnx-runtime.mirror/files/v${ONNXRUNTIME_VERSION}/${pkg}/download"
    fi

    tmpdir="$(mktemp -d -t onnxrt.XXXXXX)"
    echo "Downloading ONNX Runtime ${ONNXRUNTIME_VERSION} (${pkg})..."
    curl -L "$url" -o "$tmpdir/$pkg" || return 1

    echo "Extracting..."
    tar -xzf "$tmpdir/$pkg" -C "$tmpdir" || return 1

    root="$(find "$tmpdir" -maxdepth 1 -type d -name "onnxruntime-*" | head -n 1)"
    if [ -z "$root" ]; then
        echo "Failed to locate extracted ONNX Runtime directory."
        rm -rf "$tmpdir"
        return 1
    fi

    echo "Installing ONNX Runtime headers -> ${ONNXRUNTIME_INSTALL_PREFIX}/include/"
    sudo mkdir -p "${ONNXRUNTIME_INSTALL_PREFIX}/include"
    sudo cp -R "$root/include/"* "${ONNXRUNTIME_INSTALL_PREFIX}/include/"

    echo "Installing ONNX Runtime libs -> ${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    sudo mkdir -p "${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    sudo cp -f "$root/lib/"libonnxruntime* "${ONNXRUNTIME_INSTALL_PREFIX}/lib/"

    if ! ls "$libdir"/libonnxruntime*.dylib >/dev/null 2>&1 && \
       ! ls "$libdir"/libonnxruntime*.so*  >/dev/null 2>&1 && \
       ! ls "$libdir"/libonnxruntime*.a    >/dev/null 2>&1; then
        echo "ERROR: ONNX Runtime library did not install into $libdir"
        rm -rf "$tmpdir"
        return 1
    fi

    if [ "$os" = "Darwin" ]; then
        if [ ! -e "$libdir/libonnxruntime.dylib" ] && [ ! -e "$libdir/libonnxruntime.a" ]; then
            ver_dylib="$(ls -1 "$libdir"/libonnxruntime*.dylib 2>/dev/null | head -n 1)"
            if [ -n "$ver_dylib" ]; then
                echo "Creating symlink: $libdir/libonnxruntime.dylib -> $(basename "$ver_dylib")"
                sudo ln -sf "$(basename "$ver_dylib")" "$libdir/libonnxruntime.dylib"
            fi
        fi
    elif [ "$os" = "Linux" ]; then
        if [ ! -e "$libdir/libonnxruntime.so" ] && [ ! -e "$libdir/libonnxruntime.a" ]; then
            ver_so="$(ls -1 "$libdir"/libonnxruntime.so.* 2>/dev/null | head -n 1)"
            if [ -n "$ver_so" ]; then
                echo "Creating symlink: $libdir/libonnxruntime.so -> $(basename "$ver_so")"
                sudo ln -sf "$(basename "$ver_so")" "$libdir/libonnxruntime.so"
            fi
        fi
        sudo ldconfig
    fi

    # Auto-create the ONNX accelerator config file if GPU is present
    if [ "$use_gpu" = "1" ]; then
        echo "SCALPEL3_ONNX_ACCELERATOR=cuda" > "$CURDIR/.scalpel3_onnx.conf"
        echo "Created $CURDIR/.scalpel3_onnx.conf with CUDA accelerator."
    else
        echo "SCALPEL3_ONNX_ACCELERATOR=cpu" > "$CURDIR/.scalpel3_onnx.conf"
        echo "Created $CURDIR/.scalpel3_onnx.conf with CPU accelerator."
    fi

    rm -rf "$tmpdir"
    echo "ONNX Runtime install complete."
}


install_cudnn_if_needed() {
    if ! has_nvidia_gpu; then
        return 0
    fi

    if ldconfig -p | grep -q libcudnn.so; then
        echo "cuDNN already installed, skipping."
        return 0
    fi

    echo "NVIDIA GPU detected but cuDNN not found. Installing cuDNN..."

    local os
    os="$(uname)"
    if [ "$os" != "Linux" ]; then
        echo "cuDNN auto-install only supported on Linux."
        return 0
    fi

    source /etc/os-release

    if [ "$ID" == "ubuntu" ] || [ "$ID" == "debian" ] || [ "$ID_LIKE" == "debian" ] || [ "$ID" == "linuxmint" ]; then
        sudo apt install -y -q nvidia-cudnn
    elif [ "$ID" == "centos" ] || [ "$ID" == "fedora" ] || [ "$ID" == "rhel" ] || [ "$ID_LIKE" == "fedora" ] || [ "$ID_LIKE" == "rhel fedora" ]; then
        sudo dnf install -y cudnn
    elif [ "$ID" == "opensuse-leap" ] || [ "$ID" == "opensuse" ] || [ "$ID_LIKE" == "suse opensuse" ] || [ "$ID_LIKE" == "suse" ] || [ "$ID_LIKE" == "opensuse" ]; then
        sudo zypper -n install cudnn
    elif [ "$ID" == "garuda" ] || [ "$ID" == "manjaro" ] || [ "$ID" == "arch" ] || [ "$ID_LIKE" == "arch" ]; then
        sudo pacman -Sqy cudnn --noconfirm
    else
        echo "WARNING: Could not auto-install cuDNN for this distribution. Please install it manually."
    fi

    sudo ldconfig
}




CURDIR=`pwd`

[[ `uname -m` =~ "64" ]] ||
    {
	echo "scalpel3 works only on 64-bit platforms.";
	exit 1;
    }

if [ "$(uname)" == "Darwin" ]; then
    echo "*************************************************************************"
    echo "** USE OF blockmapfs ON macOS WILL REQUIRE ENABLING KERNEL EXTENSIONS! **"
    echo "** A NOTIFICATION WILL APPEAR WHEN YOU FIRST ATTEMPT TO USE blockmapfs **"
    echo "*************************************************************************"

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
	sudo port install macfuse
	sudo port install libjpeg-turbo
	sudo port install mpg123
	sudo port install libarchive
	sudo port install libsdl2
	sudo port install libsdl2_image
	sudo port install libsdl2_ttf
	sudo ln -fsn /opt/local/Library/Filesystems/macfuse.fs /Library/Filesystems/macfuse.fs
	CPPFLAGS="-g -I /usr/local/include -I /opt/local/include"
	LDFLAGS="-L/usr/local/lib -L/opt/local/lib"
	install_onnxruntime_prebuilt
    install_cudnn_if_needed
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
	brew install --cask macfuse
	brew install mpg123
	brew install libarchive
	brew install sdl2
	brew install sdl2_image
	brew install sdl2_ttf

	# determine paths based on architecture
	if [ "$APPLEARCH" == "arm64" ]; then
	    CPPFLAGS="-g -I /usr/local/include -I /opt/homebrew/opt/libarchive/include -I /opt/homebrew/include"
	    LDFLAGS="-L/usr/local/lib -L/opt/homebrew/opt/libarchive/lib -L/opt/homebrew/lib"
	else
	    CPPFLAGS="-g -I/usr/local/include -I/usr/local/opt/libarchive/include"
	    LDFLAGS="-L/usr/local/lib -L/usr/local/opt/libarchive/lib"
        LIBS+=" -larchive"
	fi

	# --- ONNX Runtime (needed for ELF ONNX inference)
    install_onnxruntime_prebuilt
    install_cudnn_if_needed
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

    # determine the linux distro to install build dependencies
    source /etc/os-release

    # Debian family
    if [ "$ID" == "ubuntu" ] || [ "$ID" == "debian" ] || [ "$ID_LIKE" == "debian" ] || [ "$ID" == "linuxmint" ]; then

        sudo apt update -y -q
        sudo apt install -y -q \
            software-properties-common \
            build-essential \
            curl \
            git \
            libssl-dev \
            zlib1g-dev \
            libbz2-dev \
            libreadline-dev \
            libsqlite3-dev \
            libffi-dev \
            libncurses5-dev \
            libncursesw5-dev \
            xz-utils \
            tk-dev \
            liblzma-dev \
            lzma \
            uuid-dev

        sudo apt install autotools-dev -y -q
        sudo apt install automake -y -q
        sudo apt install gettext -y -q
        sudo apt install nasm -y -q
        sudo apt install libpng-dev -y -q
        sudo apt install texinfo -y -q
        sudo apt install libz-dev -y -q
        sudo apt install libiberty-dev -y -q
        sudo apt install libndctl-dev -y -q
        sudo apt install binutils-dev -y -q
        sudo apt install xmlto -y -q
        sudo apt install libelf-dev -y -q
        sudo apt install pkg-config -y -q
        sudo apt install uuid-dev -y -q
        sudo apt install libpcre2-dev -y -q
        sudo apt install libfuse2 -y -q
        sudo apt install libfuse-dev -y -q
        sudo apt install libhdf5-dev -y -q
        sudo apt install libjpeg-turbo8 -y -q
        sudo apt install libjpeg62-turbo -y -q
        sudo apt install libmpg123-dev -y -q
        sudo apt install libarchive-dev -y -q
        sudo apt install libsdl2-dev -y -q
        sudo apt install libsdl2-image-dev -y -q
        sudo apt install libsdl2-ttf-dev -y -q

        install_onnxruntime_prebuilt
        install_cudnn_if_needed
        CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    # Fedora / RedHat family
    elif [ $ID == "centos" ] || [ $ID == "fedora" ] || [ $ID == "rhel" ] || [ $ID_LIKE == "fedora" ] || [ $ID_LIKE == "rhel fedora" ]; then
        sudo dnf install -y curl
	sudo dnf install -y cmake
        sudo dnf install -y git
        sudo dnf install -y gcc
        sudo dnf install -y which
        sudo dnf install -y openssl openssl-libs openssl-devel
        sudo dnf install -y bzip2-devel bzip2-static
        sudo dnf install -y readline compat-readline5-devel
        sudo dnf install -y libsqlite3x-devel
        sudo dnf install -y libffi-develelif
        sudo dnf install -y ncurses-devel ncurses-static
        sudo dnf install -y xz xz-devel
        sudo dnf install -y tk-devel
        sudo dnf install -y lzma-sdk-devel
        sudo dnf install -y libuuid-devel
        sudo dnf install -y automake
        sudo dnf install -y gettext gettext-devel
        sudo dnf install -y nasm
        sudo dnf install -y libpng-devel libpng-static
        sudo dnf install -y texinfo
        sudo dnf install -y binutils-devel
        sudo dnf install -y ndctl-devel
        sudo dnf install -y xmlto
        sudo dnf install -y elfutils elfutils-libs elfutils-devel elfutils-libelf elfutils-libelf-devel
        sudo dnf install -y pkgconf pkgconf-pkg-config
        sudo dnf install -y pcre2-devel
        sudo dnf install -y fuse fuse-devel
        sudo dnf install -y hdf5-devel
        sudo dnf install -y libjpeg-turbo libjpeg-turbo-devel
        sudo dnf install -y mpg123
        sudo dnf install -y libarchive libarchive-devel
        sudo dnf install -y SDL2-devel SDL2_image-devel SDL2_ttf-devel

        install_onnxruntime_prebuilt
        install_cudnn_if_needed
        CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    elif [ $ID == "opensuse-leap" ] || [ $ID == "opensuse" ] || [ $ID_LIKE == "suse opensuse" ] || [ $ID_LIKE == "suse" ] || [ $ID_LIKE == "opensuse" ]; then
        sudo zypper -n install gcc
        sudo zypper -n install make
        sudo zypper -n install curl
	sudo zypper -n install cmake
        sudo zypper -n install git
        sudo zypper -n install autobuild
        sudo zypper -n install openssl
        sudo zypper -n install libopenssl-devel
        sudo zypper -n install zlib-devel
        sudo zypper -n install libbz2-devel
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
        sudo zypper -n install libfuse2
        sudo zypper -n install fuse-devel
        sudo zypper -n install hdf5-devel
        sudo zypper -n install libjpeg-turbo
        sudo zypper -n install libjpeg62-devel
        sudo zypper -n install mpg123
        sudo zypper -n install libarchive-devel
        sudo zypper -n install libSDL2-devel SDL2_image-devel SDL2_ttf-devel

        install_onnxruntime_prebuilt
        install_cudnn_if_needed
    	CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    # Arch family
    elif [ $ID == "garuda" ] || [ $ID == "manjaro" ] || [ $ID == "arch" ] || [ $ID_LIKE == "arch" ]; then
        sudo pacman -Sqy gcc --noconfirm
        sudo pacman -Sqy make --noconfirm
        sudo pacman -Sqy curl --noconfirm
	sudo pacman -Sqy cmake --noconfirm
        sudo pacman -Sqy git --noconfirm
        sudo pacman -Sqy openssl --noconfirm
        sudo pacman -Sqy bzip2 --noconfirm
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
        sudo pacman -Sqy fuse2 --noconfirm
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

        install_onnxruntime_prebuilt
        install_cudnn_if_needed
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
    CPPFLAGS="-I/usr/local/include $CPPFLAGS" \
    LDFLAGS="-L/usr/local/lib $LDFLAGS -Wl,-rpath,/usr/local/lib" \
    LIBS="$LIBS" \
    ./configure &&
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
    echo -e '\033[0m';
    }
