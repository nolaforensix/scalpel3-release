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
ONNXRUNTIME_VERSION="1.26.0"
ONNXRUNTIME_INSTALL_PREFIX="/usr/local"
ONNXRUNTIME_CUDA_MAJOR="13"
SCALPEL3_CUDA_RUNTIME_VERSION="onnxruntime-${ONNXRUNTIME_VERSION}-cuda-${ONNXRUNTIME_CUDA_MAJOR}-cudnn-9.24"
SCALPEL3_CUDA_RUNTIME_DIR="/usr/local/lib/scalpel3-cuda"
SCALPEL3_TENSORRT_RUNTIME_VERSION="tensorrt-cu13-major-10"
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

verify_macfuse_runtime() {
    local bundle="/Library/Filesystems/macfuse.fs"
    local loader="$bundle/Contents/Resources/load_macfuse"

    if [ ! -x "$loader" ]; then
        echo "ERROR: The macFUSE runtime is not installed at $bundle."
        return 1
    fi

    if ! "$loader" >/dev/null 2>&1; then
        echo "ERROR: macFUSE is installed but its kernel extension is not active."
        echo "       Approve macFUSE in System Settings under Privacy & Security."
        echo "       Restart macOS if requested, then run this script again."
        return 1
    fi

    echo "macFUSE runtime verified."
    return 0
}

install_onnxruntime_prebuilt() {
    local arch libdir marker os pkg root tmpdir url ver_dylib ver_so

    os="$(uname)"
    arch="$(uname -m)"
    libdir="${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    marker="$libdir/.scalpel3-onnxruntime-version"

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
        Linux)
            case "$arch" in
                x86_64|amd64)
                    if has_nvidia_hardware && ! has_nvidia_gpu; then
                        echo "ERROR: NVIDIA GPU hardware is present, but the NVIDIA driver"
                        echo "       cannot enumerate it. Repair the driver, verify that"
                        echo "       'nvidia-smi -L' succeeds, and rerun this script."
                        return 1
                    fi
                    if onnxruntime_cuda_prebuilt_available; then
                        pkg="onnxruntime-linux-x64-gpu_cuda${ONNXRUNTIME_CUDA_MAJOR}-${ONNXRUNTIME_VERSION}.tgz"
                        echo "NVIDIA GPU detected, using CUDA ${ONNXRUNTIME_CUDA_MAJOR}-enabled ONNX Runtime."
                    else
                        pkg="onnxruntime-linux-x64-${ONNXRUNTIME_VERSION}.tgz"
                        echo "No NVIDIA GPU detected, using CPU ONNX Runtime."
                    fi
                    ;;
                aarch64|arm64)
                    if has_nvidia_hardware; then
                        echo "ERROR: ONNX Runtime does not publish a CUDA-enabled Linux ARM64 archive."
                        echo "       Build ONNX Runtime with CUDA support or explicitly configure"
                        echo "       Scalpel3 for CPU inference on this platform."
                        return 1
                    fi
                    pkg="onnxruntime-linux-aarch64-${ONNXRUNTIME_VERSION}.tgz"
                    ;;
                *)
                    echo "Unsupported Linux arch for ONNX Runtime: $arch"
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

private_cuda_runtime_complete() {
    local library root

    root="$1"
    for library in \
        nvidia/cu13/lib/libcudart.so.13 \
        nvidia/cu13/lib/libcublasLt.so.13 \
        nvidia/cu13/lib/libcublas.so.13 \
        nvidia/cu13/lib/libcurand.so.10 \
        nvidia/cu13/lib/libcufft.so.12 \
        nvidia/cu13/lib/libnvJitLink.so.13 \
        'nvidia/cu13/lib/libnvrtc-builtins.so.13.*' \
        nvidia/cu13/lib/libnvrtc.so.13 \
        nvidia/cudnn/lib/libcudnn_graph.so.9 \
        nvidia/cudnn/lib/libcudnn_ops.so.9 \
        nvidia/cudnn/lib/libcudnn_adv.so.9 \
        nvidia/cudnn/lib/libcudnn_cnn.so.9 \
        nvidia/cudnn/lib/libcudnn_engines_precompiled.so.9 \
        nvidia/cudnn/lib/libcudnn_engines_runtime_compiled.so.9 \
        nvidia/cudnn/lib/libcudnn_engines_tensor_ir.so.9 \
        nvidia/cudnn/lib/libcudnn_ext.so.9 \
        nvidia/cudnn/lib/libcudnn_heuristic.so.9 \
        nvidia/cudnn/lib/libcudnn.so.9
    do
        if ! compgen -G "$root/$library" >/dev/null; then
            return 1
        fi
    done

    return 0
}

verify_private_cuda_runtime() {
    python3 - "$1" <<'PY'
import ctypes
import glob
import os
import sys

root = os.path.realpath(sys.argv[1])
patterns = [
    "nvidia/cu13/lib/libcudart.so.13",
    "nvidia/cu13/lib/libcublasLt.so.13",
    "nvidia/cu13/lib/libcublas.so.13",
    "nvidia/cu13/lib/libcurand.so.10",
    "nvidia/cu13/lib/libcufft.so.12",
    "nvidia/cu13/lib/libnvJitLink.so.13",
    "nvidia/cu13/lib/libnvrtc-builtins.so.13.*",
    "nvidia/cu13/lib/libnvrtc.so.13",
    "nvidia/cudnn/lib/libcudnn_graph.so.9",
    "nvidia/cudnn/lib/libcudnn_ops.so.9",
    "nvidia/cudnn/lib/libcudnn_adv.so.9",
    "nvidia/cudnn/lib/libcudnn_cnn.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_precompiled.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_runtime_compiled.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_tensor_ir.so.9",
    "nvidia/cudnn/lib/libcudnn_ext.so.9",
    "nvidia/cudnn/lib/libcudnn_heuristic.so.9",
    "nvidia/cudnn/lib/libcudnn.so.9",
]

handles = []
for pattern in patterns:
    matches = glob.glob(os.path.join(root, pattern))
    if len(matches) != 1:
        raise SystemExit(f"runtime pattern {pattern} matched {len(matches)} files")
    handles.append(ctypes.CDLL(matches[0], mode=ctypes.RTLD_GLOBAL))

runtime_version = ctypes.c_int()
if handles[0].cudaRuntimeGetVersion(ctypes.byref(runtime_version)) != 0:
    raise SystemExit("cudaRuntimeGetVersion failed")
handles[-1].cudnnGetVersion.restype = ctypes.c_size_t
cudnn_version = handles[-1].cudnnGetVersion()
if runtime_version.value < 13000:
    raise SystemExit(f"CUDA runtime {runtime_version.value} is older than CUDA 13")
if cudnn_version < 92400:
    raise SystemExit(f"cuDNN runtime {cudnn_version} is older than cuDNN 9.24")

print(
    f"Private CUDA runtime verified: CUDA {runtime_version.value // 1000}."
    f"{(runtime_version.value % 1000) // 10}, "
    f"cuDNN {cudnn_version // 10000}.{(cudnn_version % 10000) // 100}."
)
PY
}

install_python_pip() {
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -q && sudo apt-get install -y -q python3-pip
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y python3-pip
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y python3-pip
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper -n install python3-pip
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --needed --noconfirm python-pip
    else
        echo "ERROR: Could not install Python pip with a supported package manager."
        return 1
    fi
}

private_tensorrt_runtime_complete() {
    local library root

    root="$1"
    for library in \
        libnvinfer.so.10 \
        libnvinfer_plugin.so.10 \
        libnvonnxparser.so.10
    do
        if [ ! -f "$root/$library" ]; then
            return 1
        fi
    done

    return 0
}

verify_private_tensorrt_runtime() {
    python3 - "$SCALPEL3_CUDA_RUNTIME_DIR" "$1" <<'PY'
import ctypes
import glob
import os
import sys

cuda_root = os.path.realpath(sys.argv[1])
tensorrt_root = os.path.realpath(sys.argv[2])
cuda_patterns = [
    "nvidia/cu13/lib/libcudart.so.13",
    "nvidia/cu13/lib/libcublasLt.so.13",
    "nvidia/cu13/lib/libcublas.so.13",
    "nvidia/cu13/lib/libcurand.so.10",
    "nvidia/cu13/lib/libcufft.so.12",
    "nvidia/cu13/lib/libnvJitLink.so.13",
    "nvidia/cu13/lib/libnvrtc-builtins.so.13.*",
    "nvidia/cu13/lib/libnvrtc.so.13",
    "nvidia/cudnn/lib/libcudnn_graph.so.9",
    "nvidia/cudnn/lib/libcudnn_ops.so.9",
    "nvidia/cudnn/lib/libcudnn_adv.so.9",
    "nvidia/cudnn/lib/libcudnn_cnn.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_precompiled.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_runtime_compiled.so.9",
    "nvidia/cudnn/lib/libcudnn_engines_tensor_ir.so.9",
    "nvidia/cudnn/lib/libcudnn_ext.so.9",
    "nvidia/cudnn/lib/libcudnn_heuristic.so.9",
    "nvidia/cudnn/lib/libcudnn.so.9",
]

handles = []
for pattern in cuda_patterns:
    matches = glob.glob(os.path.join(cuda_root, pattern))
    if len(matches) != 1:
        raise SystemExit(f"CUDA runtime pattern {pattern} matched {len(matches)} files")
    handles.append(ctypes.CDLL(matches[0], mode=ctypes.RTLD_GLOBAL))

for library in ("libnvinfer.so.10", "libnvinfer_plugin.so.10",
                "libnvonnxparser.so.10"):
    path = os.path.join(tensorrt_root, library)
    if not os.path.isfile(path):
        raise SystemExit(f"TensorRT library is missing: {path}")
    handles.append(ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL))

print("Private TensorRT 10 runtime verified.")
PY
}

install_private_tensorrt_runtime_if_available() {
    local backup marker runtime staged tmpdir

    runtime="$SCALPEL3_CUDA_RUNTIME_DIR/tensorrt_libs"
    marker="$runtime/.scalpel3-tensorrt-version"
    if [ -f "$marker" ] && \
       [ "$(cat "$marker")" = "$SCALPEL3_TENSORRT_RUNTIME_VERSION" ] && \
       private_tensorrt_runtime_complete "$runtime" && \
       verify_private_tensorrt_runtime "$runtime"; then
        echo "Scalpel3 private TensorRT 10 runtime already installed."
        return 0
    fi

    mkdir -p "$SCALPEL3_INSTALL_TMPDIR"
    tmpdir="$(mktemp -d "$SCALPEL3_INSTALL_TMPDIR/scalpel3-tensorrt.XXXXXX")"
    echo "Installing optional TensorRT 10 acceleration for ELF validation..."
    if ! python3 -m pip install \
            --disable-pip-version-check \
            --no-cache-dir \
            --no-deps \
            --only-binary=:all: \
            --extra-index-url https://pypi.nvidia.com \
            --target "$tmpdir/runtime" \
            'tensorrt-cu13-libs>=10,<11'; then
        rm -rf "$tmpdir"
        echo "WARNING: TensorRT could not be installed; Scalpel3 will use CUDA."
        return 0
    fi

    runtime="$tmpdir/runtime/tensorrt_libs"
    find "$runtime" -maxdepth 1 -type f \
        -name 'libnvinfer_builder_resource_win_*' -delete
    if ! private_tensorrt_runtime_complete "$runtime" || \
       ! verify_private_tensorrt_runtime "$runtime"; then
        rm -rf "$tmpdir"
        echo "WARNING: TensorRT could not be verified; Scalpel3 will use CUDA."
        return 0
    fi

    staged="$SCALPEL3_CUDA_RUNTIME_DIR/tensorrt_libs.new.$$"
    backup="$SCALPEL3_CUDA_RUNTIME_DIR/tensorrt_libs.old.$$"
    sudo rm -rf "$staged" "$backup"
    sudo mkdir -p "$staged"
    sudo cp -RP "$runtime/." "$staged/"
    printf '%s\n' "$SCALPEL3_TENSORRT_RUNTIME_VERSION" \
        | sudo tee "$staged/.scalpel3-tensorrt-version" >/dev/null
    if ! private_tensorrt_runtime_complete "$staged" || \
       ! verify_private_tensorrt_runtime "$staged"; then
        sudo rm -rf "$staged"
        rm -rf "$tmpdir"
        echo "WARNING: Staged TensorRT runtime failed verification; using CUDA."
        return 0
    fi

    if [ -e "$SCALPEL3_CUDA_RUNTIME_DIR/tensorrt_libs" ]; then
        if ! sudo mv "$SCALPEL3_CUDA_RUNTIME_DIR/tensorrt_libs" "$backup"; then
            sudo rm -rf "$staged"
            rm -rf "$tmpdir"
            echo "WARNING: Existing TensorRT runtime could not be replaced; using CUDA."
            return 0
        fi
    fi
    if ! sudo mv "$staged" "$SCALPEL3_CUDA_RUNTIME_DIR/tensorrt_libs"; then
        if [ -e "$backup" ]; then
            sudo mv "$backup" "$SCALPEL3_CUDA_RUNTIME_DIR/tensorrt_libs"
        fi
        rm -rf "$tmpdir"
        echo "WARNING: TensorRT activation failed; Scalpel3 will use CUDA."
        return 0
    fi
    sudo rm -rf "$backup"
    rm -rf "$tmpdir"
    echo "Scalpel3 private TensorRT runtime installed."
    return 0
}


install_private_cuda_runtime_if_needed() {
    local arch backup marker os staged tmpdir

    if ! has_nvidia_gpu; then
        return 0
    fi

    os="$(uname)"
    arch="$(uname -m)"
    if [ "$os" != "Linux" ] || { [ "$arch" != "x86_64" ] && [ "$arch" != "amd64" ]; }; then
        echo "Private CUDA runtime installation is supported on Linux x86_64 only."
        return 0
    fi

    marker="$SCALPEL3_CUDA_RUNTIME_DIR/.scalpel3-runtime-version"
    if [ -f "$marker" ] && \
       [ "$(cat "$marker")" = "$SCALPEL3_CUDA_RUNTIME_VERSION" ] && \
       private_cuda_runtime_complete "$SCALPEL3_CUDA_RUNTIME_DIR" && \
       verify_private_cuda_runtime "$SCALPEL3_CUDA_RUNTIME_DIR"; then
        echo "Scalpel3 private CUDA 13/cuDNN 9.24 runtime already installed."
        install_private_tensorrt_runtime_if_available
        return 0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        echo "ERROR: Python 3 is required to install Scalpel3's private CUDA runtime."
        return 1
    fi

    if ! python3 -m pip --version >/dev/null 2>&1; then
        if ! install_python_pip; then
            return 1
        fi
    fi

    mkdir -p "$SCALPEL3_INSTALL_TMPDIR"
    tmpdir="$(mktemp -d "$SCALPEL3_INSTALL_TMPDIR/scalpel3-cuda.XXXXXX")"
    echo "Installing Scalpel3's private CUDA 13/cuDNN 9.24 runtime..."
    if ! python3 -m pip install \
            --disable-pip-version-check \
            --no-cache-dir \
            --no-deps \
            --only-binary=:all: \
            --target "$tmpdir/runtime" \
            'nvidia-cuda-runtime>=13,<14' \
            'nvidia-cublas>=13,<14' \
            'nvidia-cufft>=12,<13' \
            'nvidia-curand>=10,<11' \
            'nvidia-cudnn-cu13>=9.24,<10' \
            'nvidia-cuda-nvrtc>=13,<14' \
            'nvidia-nvjitlink>=13,<14'; then
        rm -rf "$tmpdir"
        echo "ERROR: Failed to install Scalpel3's private CUDA runtime."
        return 1
    fi

    if ! private_cuda_runtime_complete "$tmpdir/runtime"; then
        rm -rf "$tmpdir"
        echo "ERROR: The downloaded private CUDA runtime is incomplete."
        return 1
    fi
    if ! verify_private_cuda_runtime "$tmpdir/runtime"; then
        rm -rf "$tmpdir"
        echo "ERROR: The downloaded private CUDA runtime could not be loaded."
        return 1
    fi

    staged="${SCALPEL3_CUDA_RUNTIME_DIR}.new.$$"
    backup="${SCALPEL3_CUDA_RUNTIME_DIR}.old.$$"
    sudo rm -rf "$staged" "$backup"
    sudo mkdir -p "$staged"
    sudo cp -RP "$tmpdir/runtime/." "$staged/"
    printf '%s\n' "$SCALPEL3_CUDA_RUNTIME_VERSION" \
        | sudo tee "$staged/.scalpel3-runtime-version" \
          >/dev/null

    if ! private_cuda_runtime_complete "$staged" || \
       ! verify_private_cuda_runtime "$staged"; then
        sudo rm -rf "$staged"
        rm -rf "$tmpdir"
        echo "ERROR: The staged private CUDA runtime is incomplete or unusable."
        return 1
    fi

    if [ -e "$SCALPEL3_CUDA_RUNTIME_DIR" ]; then
        if ! sudo mv "$SCALPEL3_CUDA_RUNTIME_DIR" "$backup"; then
            sudo rm -rf "$staged"
            rm -rf "$tmpdir"
            return 1
        fi
    fi
    if ! sudo mv "$staged" "$SCALPEL3_CUDA_RUNTIME_DIR"; then
        if [ -e "$backup" ]; then
            sudo mv "$backup" "$SCALPEL3_CUDA_RUNTIME_DIR"
        fi
        rm -rf "$tmpdir"
        echo "ERROR: Failed to activate Scalpel3's private CUDA runtime."
        return 1
    fi
    sudo rm -rf "$backup"
    rm -rf "$tmpdir"

    echo "Scalpel3 private CUDA runtime installed in $SCALPEL3_CUDA_RUNTIME_DIR."
    install_private_tensorrt_runtime_if_available
    return 0
}




CURDIR=`pwd`

reconstruct_elf_onnx_model_if_needed() {
    local model_dir model chunk_dir part_prefix tmp_model part_count

    model_dir="$CURDIR/src/exe_vision/unix"
    model="$model_dir/elf_unet.onnx"
    chunk_dir="$model_dir/elf_onnx"
    part_prefix="$chunk_dir/elf_unet.onnx.part_"
    tmp_model="$model.tmp"

    if [ -f "$model" ]; then
        echo "ELF ONNX model already exists: $model"
        return 0
    fi

    if [ ! -d "$chunk_dir" ]; then
        echo "ERROR: ELF ONNX chunk directory not found: $chunk_dir"
        return 1
    fi

    part_count=$(find "$chunk_dir" -maxdepth 1 -type f -name 'elf_unet.onnx.part_*' | wc -l | tr -d ' ')

    if [ "$part_count" -eq 0 ]; then
        echo "ERROR: No ELF ONNX model chunks found in: $chunk_dir"
        return 1
    fi

    echo "Reconstructing ELF ONNX model from $part_count chunks..."

    rm -f "$tmp_model"

    find "$chunk_dir" -maxdepth 1 -type f -name 'elf_unet.onnx.part_*' \
        | LC_ALL=C sort \
        | while IFS= read -r part; do
            cat "$part" >> "$tmp_model"
        done

    if [ ! -s "$tmp_model" ]; then
        echo "ERROR: Failed to reconstruct ELF ONNX model."
        rm -f "$tmp_model"
        return 1
    fi

    mv "$tmp_model" "$model"

    echo "ELF ONNX model reconstructed:"
    ls -lh "$model"

    return 0
}

[[ `uname -m` =~ "64" ]] ||
    {
	echo "scalpel3 works only on 64-bit platforms.";
	exit 1;
    }

reconstruct_elf_onnx_model_if_needed || exit 1

if [ "$(uname)" == "Darwin" ]; then
    echo "*************************************************************************"
    echo "** blockmapfs on macOS requires approving the macFUSE kernel extension. **"
    echo "** A first installation may require a restart and rerunning this script. **"
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
	"$CURDIR/install_macfuse_link.sh" || exit 1
	CPPFLAGS="-g -I /usr/local/include -I /opt/local/include"
	LDFLAGS="-L/usr/local/lib -L/opt/local/lib"
	install_onnxruntime_prebuilt || exit 1
    install_private_cuda_runtime_if_needed || exit 1
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
    install_onnxruntime_prebuilt || exit 1
    install_private_cuda_runtime_if_needed || exit 1
	CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
    LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
    LIBS+=" -lonnxruntime"

    else
		echo "Neither MacPorts nor Homebrew was detected. Dependencies will have to be installed manually."
		sleep 5
	fi

    verify_fuse3_development_files || exit 1
    verify_macfuse_runtime || exit 1

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
        sudo apt install fuse3 -y -q
        sudo apt install libfuse3-dev -y -q
        sudo apt install libhdf5-dev -y -q
        sudo apt install libjpeg-turbo8 -y -q
        sudo apt install libjpeg62-turbo -y -q
        sudo apt install libmpg123-dev -y -q
        sudo apt install libarchive-dev -y -q
        sudo apt install libsdl2-dev -y -q
        sudo apt install libsdl2-image-dev -y -q
        sudo apt install libsdl2-ttf-dev -y -q

        install_onnxruntime_prebuilt || exit 1
        install_private_cuda_runtime_if_needed || exit 1
        CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    # Fedora / RedHat family
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y curl
	sudo dnf install -y cmake
        sudo dnf install -y git
        sudo dnf install -y gcc
        sudo dnf install -y which
        sudo dnf install -y openssl openssl-libs openssl-devel
        sudo dnf install -y bzip2-devel bzip2-static
        sudo dnf install -y readline compat-readline5-devel
        sudo dnf install -y libsqlite3x-devel
        sudo dnf install -y libffi-devel
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
        sudo dnf install -y fuse3 fuse3-devel
        sudo dnf install -y hdf5-devel
        sudo dnf install -y libjpeg-turbo libjpeg-turbo-devel
        sudo dnf install -y mpg123
        sudo dnf install -y libarchive libarchive-devel
        sudo dnf install -y SDL2-devel SDL2_image-devel SDL2_ttf-devel

        install_onnxruntime_prebuilt || exit 1
        install_private_cuda_runtime_if_needed || exit 1
        CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    elif command -v zypper >/dev/null 2>&1; then
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
        sudo zypper -n install fuse3
        sudo zypper -n install fuse3-devel
        sudo zypper -n install hdf5-devel
        sudo zypper -n install libjpeg-turbo
        sudo zypper -n install libjpeg62-devel
        sudo zypper -n install mpg123
        sudo zypper -n install libarchive-devel
        sudo zypper -n install libSDL2-devel SDL2_image-devel SDL2_ttf-devel

        install_onnxruntime_prebuilt || exit 1
        install_private_cuda_runtime_if_needed || exit 1
    	CPPFLAGS+=" -I${ONNXRUNTIME_INSTALL_PREFIX}/include"
        LDFLAGS+=" -L${ONNXRUNTIME_INSTALL_PREFIX}/lib"
        LIBS+=" -lonnxruntime"

    # Arch family
    elif command -v pacman >/dev/null 2>&1; then
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
        install_private_cuda_runtime_if_needed || exit 1
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
