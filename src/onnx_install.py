#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2021-2026 Golden G. Richard III and contributors.
# See LICENSE.md for licensing and commercial licensing contact information.

"""Select and verify Linux ONNX libraries without replacing shared installations."""

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import urllib.error


SOURCE = Path(__file__).resolve().parent
MODES = ("auto", "cpu", "12", "13")
LEGACY_RUNTIME = Path("/usr/local/lib/scalpel3-cuda")
CUDA_DOC = "https://docs.nvidia.com/cuda/cuda-installation-guide-linux/"
ORT_DOC = "https://onnxruntime.ai/docs/execution-providers/CUDA-ExecutionProvider.html"


def build_path(path):
    path = str(path)
    if any(char.isspace() or char in ',"\\' for char in path):
        raise ValueError(f"Build paths cannot contain whitespace, commas, quotes or backslashes: {path}")
    return path


def run(command, **kwargs):
    return subprocess.run([str(arg) for arg in command], check=True, text=True, **kwargs)


def clean_environment():
    env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1")
    for name in ("LD_LIBRARY_PATH", "LD_PRELOAD", "LIBRARY_PATH", "CPATH",
                 "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH"):
        env.pop(name, None)
    return env


def cuda_major(prefix):
    provider = prefix / "lib/libonnxruntime_providers_cuda.so"
    if not provider.is_file():
        return 0
    dynamic = run(["readelf", "-d", provider], capture_output=True).stdout
    matches = re.findall(r"\(NEEDED\).*\[libcudart\.so\.(\d+)\]", dynamic)
    if len(matches) != 1 or matches[0] not in ("12", "13"):
        raise ValueError(f"Unsupported CUDA dependency in {provider}: {matches}")
    return int(matches[0])


def runtime_majors(root):
    if root == "system":
        try:
            listing = run(["/sbin/ldconfig", "-p"], capture_output=True).stdout
        except (OSError, subprocess.CalledProcessError):
            return []
        return [major for major in (12, 13) if f"libcudart.so.{major} " in listing]
    root = Path(root)
    return [major for major, library in (
        (12, "nvidia/cuda_runtime/lib/libcudart.so.12"),
        (13, "nvidia/cu13/lib/libcudart.so.13")) if (root / library).is_file()]


def hardware():
    present = False
    for device in Path("/sys/bus/pci/devices").glob("*"):
        try:
            if (device / "vendor").read_text().strip() == "0x10de":
                present |= int((device / "class").read_text(), 16) >> 16 == 3
        except (OSError, ValueError):
            pass
    try:
        # Driver API only: this does not create a CUDA context or reserve GPU memory.
        driver = ctypes.CDLL("libcuda.so.1")
        driver_version = ctypes.c_int()
        if driver.cuDriverGetVersion(ctypes.byref(driver_version)) != 0:
            raise ValueError("cuDriverGetVersion failed")
        rows = run(["nvidia-smi", "--query-gpu=uuid,compute_cap",
                    "--format=csv,noheader,nounits"], capture_output=True, timeout=15).stdout
        devices = []
        visible = os.environ.get("CUDA_VISIBLE_DEVICES")
        for index, row in enumerate(rows.splitlines()):
            uuid, capability = (value.strip() for value in row.split(","))
            devices.append((index, uuid, float(capability)))
        if visible is not None:
            selected = []
            for token in visible.split(","):
                matches = [device for device in devices
                           if token == str(device[0]) or
                           (token.startswith("GPU-") and device[1].startswith(token))]
                if len(matches) != 1 or matches[0] in selected:
                    break
                selected.append(matches[0])
            devices = selected
        return present, devices, driver_version.value
    except (OSError, ValueError, subprocess.SubprocessError):
        return present, [], 0


class Probe:
    def __init__(self, directory):
        self.directory = directory
        self.binaries = {}
        self.env = clean_environment()

    def binary(self, prefix):
        prefix = prefix.resolve()
        if prefix in self.binaries:
            return self.binaries[prefix]
        include, lib = prefix / "include", prefix / "lib"
        for header in ("onnxruntime_c_api.h", "onnxruntime_cxx_api.h",
                       "onnxruntime_cxx_inline.h", "onnxruntime_float16.h"):
            if not (include / header).is_file():
                raise ValueError(f"Missing {include / header}")
        api = (include / "onnxruntime_c_api.h").read_text()
        for required in ("ORT_API2_STATUS(AddFreeDimensionOverrideByName",
                         "ORT_API2_STATUS(SessionOptionsAppendExecutionProvider,"):
            if required not in api:
                raise ValueError(f"Required ONNX API missing in {include}")
        major = cuda_major(prefix)
        build = self.directory / str(len(self.binaries))
        build.mkdir(exist_ok=True)
        cc = shlex.split(os.environ.get("CC", "cc"))
        cxx = shlex.split(os.environ.get("CXX", "c++"))
        for source in ("onnx_providers", "gpu_meminfo"):
            run(cc + ["-std=gnu11", "-O2", "-I" + str(include),
                      f"-DSCALPEL3_CUDA_MAJOR={major}",
                      "-c", SOURCE / (source + ".c"), "-o", build / (source + ".o")],
                capture_output=True, env=self.env, timeout=60)
        binary = build / "probe"
        run(cxx + ["-std=c++17", "-O2", "-I" + str(include),
                   SOURCE / "onnx_install_probe.cpp", build / "onnx_providers.o",
                   build / "gpu_meminfo.o", "-L" + str(lib), "-Wl,-rpath," + str(lib),
                   "-lonnxruntime", "-ldl", "-lm", "-o", binary],
            capture_output=True, env=self.env, timeout=60)
        self.binaries[prefix] = (binary, major)
        return binary, major

    def check(self, prefix, runtime, provider):
        build_path(prefix)
        build_path(runtime)
        binary, major = self.binary(prefix)
        env = dict(self.env, SCALPEL3_CUDA_RUNTIME_DIR=str(runtime))
        # Each attempt is a fresh process: failed CUDA loads cannot contaminate the next.
        result = run([binary, provider], env=env, capture_output=True, timeout=60)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        loaded = Path(values["ORT_LIBRARY"]).resolve()
        if loaded != (prefix / "lib/libonnxruntime.so").resolve():
            raise ValueError(f"ONNX loader selected {loaded}, not {prefix}")
        if values.get("INFERENCE") != "PASS":
            raise ValueError("Inference did not complete")
        return {"prefix": str(prefix.resolve()), "runtime": str(runtime),
                "cuda_major": major, "provider": values["PROVIDER"],
                "version": values["ORT_VERSION"], "description": values["RUNTIME"]}


def download_ort(base, version, major):
    arch = {"x86_64": "x64", "aarch64": "aarch64"}.get(platform.machine())
    if arch is None or (major and arch != "x64"):
        raise ValueError("No official ONNX CUDA archive for this architecture; provide a custom prefix")
    flavor = "cpu" if not major else f"cuda{major}"
    destination = base / f"onnxruntime-{version}-{arch}-{flavor}"
    if (destination / ".complete").is_file():
        return destination
    suffix = "-gpu" if major == 12 else "-gpu_cuda13" if major == 13 else ""
    name = f"onnxruntime-linux-{arch}{suffix}-{version}.tgz"
    url = f"https://api.github.com/repos/microsoft/onnxruntime/releases/tags/v{version}"
    with urllib.request.urlopen(url, timeout=30) as response:
        release = json.load(response)
    asset = next((item for item in release["assets"] if item["name"] == name), None)
    if not asset or not re.fullmatch(r"sha256:[a-f0-9]{64}", asset.get("digest", "")):
        raise ValueError(f"No archive with a SHA256 digest published for {name}")
    print(f"Downloading ONNX Runtime {version} ({flavor}); shared libraries will not be changed.", flush=True)
    with tempfile.TemporaryDirectory(prefix=".onnx-download-", dir=base) as work:
        work = Path(work)
        archive = work / name
        run(["curl", "--fail", "--location", "--retry", "3", "--connect-timeout", "30",
             asset["browser_download_url"], "-o", archive])
        digest = hashlib.sha256()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if "sha256:" + digest.hexdigest() != asset["digest"]:
            raise ValueError("ONNX download checksum mismatch")
        extracted = work / "extracted"
        extracted.mkdir()
        with tarfile.open(archive, "r:gz") as bundle:
            # data_filter also rejects links/devices that escape the extraction directory.
            if hasattr(tarfile, "data_filter"):
                bundle.extractall(extracted, filter="data")
            else:
                raise ValueError("Python needs tarfile.data_filter (Python 3.12 or a security-updated older release)")
        roots = list(extracted.glob("onnxruntime-*"))
        if len(roots) != 1:
            raise ValueError("Unexpected ONNX archive layout")
        root = roots[0]
        for notice in ("LICENSE", "ThirdPartyNotices.txt"):
            if not (root / notice).is_file():
                raise ValueError(f"ONNX archive is missing {notice}")
        (root / ".complete").write_text(asset["digest"] + "\n")
        # Never overwrite an incomplete or externally supplied installation.
        root.rename(destination)
    return destination


def install_cuda(base, major, devices):
    legacy = any(capability < 7.5 for _, _, capability in devices)
    if major == 13 and legacy:
        raise ValueError("CUDA 13 does not support every visible GPU; use --cuda=12")
    if legacy and any(capability >= 10 for _, _, capability in devices):
        raise ValueError("Legacy and Blackwell GPUs need different cuDNN generations; select GPUs with CUDA_VISIBLE_DEVICES")
    if legacy:
        cudnn = "nvidia-cudnn-cu12>=9,<9.11"
    else:
        cudnn = f"nvidia-cudnn-cu{major}>=9.24,<10"
    if major == 12:
        packages = ["nvidia-cuda-runtime-cu12>=12.8,<13", "nvidia-cublas-cu12>=12,<13",
                    "nvidia-cufft-cu12>=11,<12", "nvidia-curand-cu12>=10,<11",
                    "nvidia-cuda-nvrtc-cu12>=12.8,<13", "nvidia-nvjitlink-cu12>=12.8,<13", cudnn]
    else:
        packages = ["nvidia-cuda-runtime>=13,<14", "nvidia-cublas>=13,<14",
                    "nvidia-cufft>=12,<13", "nvidia-curand>=10,<11",
                    "nvidia-cuda-nvrtc>=13,<14", "nvidia-nvjitlink>=13,<14", cudnn]
    profile = "legacy" if legacy else "current"
    target = base / f"cuda{major}-cudnn9-{profile}"
    if (target / ".complete").is_file():
        return str(target)
    if target.exists():
        raise ValueError(f"Incomplete private installation at {target}; inspect it before retrying")
    if shutil.disk_usage(base).free < 8 * 1024**3:
        raise ValueError("At least 8 GiB of free disk space is needed for the private CUDA installation")
    print(f"Installing CUDA {major}/cuDNN in {target}. No driver or system library changes.", flush=True)
    with tempfile.TemporaryDirectory(prefix=".cuda-install-", dir=base) as work:
        root = Path(work) / "runtime"
        run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
             "--no-cache-dir", "--no-deps", "--only-binary=:all:", "--target", root] + packages,
            env=dict(clean_environment(), TMPDIR=work))
        (root / ".complete").write_text("\n".join(packages) + "\n")
        root.rename(target)
    return str(target)


def detail(error):
    if isinstance(error, subprocess.CalledProcessError):
        return (error.stderr or error.stdout or str(error)).strip()
    return str(error)


def unique(values):
    return list(dict.fromkeys(value for value in values if value is not None))


def select(args, base, work):
    previous = {}
    if args.output.is_file():
        try:
            previous = json.loads(args.output.read_text())
        except (ValueError, OSError):
            pass
    prefixes = [Path(value).resolve() for value in unique([
        os.environ.get("ONNXRUNTIME_INSTALL_PREFIX"), previous.get("prefix"),
        "/usr/local", "/usr", *sorted(str(path) for path in base.glob("onnxruntime-*") if path.is_dir())])]
    explicit_root = os.environ.get("SCALPEL3_CUDA_RUNTIME_DIR")
    if explicit_root and explicit_root != "system":
        explicit_root = str(Path(explicit_root).expanduser().resolve())
    roots = unique([explicit_root]) if explicit_root else unique([
        previous.get("runtime"), str(LEGACY_RUNTIME),
        *sorted(str(path) for path in base.glob("cuda*-cudnn9-*") if path.is_dir()), "system"])
    present, devices, driver_version = hardware()
    requested = int(args.mode) if args.mode in ("12", "13") else 0
    probe = Probe(work)
    failures = []

    def attempt(prefix, root, accelerator):
        try:
            major = cuda_major(prefix)
            if accelerator and (major == 0 or (requested and requested != major)):
                return None
            results = []
            for device in devices if accelerator else [None]:
                provider = "cpu"
                # onnx_providers accepts numeric visible ordinals after ':'.
                env_visible = os.environ.get("CUDA_VISIBLE_DEVICES")
                if device:
                    visible_index = devices.index(device) if env_visible is not None else device[0]
                    provider = f"cuda:{visible_index}"
                results.append(probe.check(prefix, root, provider))
            if not results:
                return None
            result = results[0]
            result["devices_checked"] = [device[1] for device in devices] if accelerator else []
            print(f"Verified ONNX {result['version']} at {prefix}: {result['provider']}.", flush=True)
            if result["description"]:
                print(result["description"], flush=True)
            return result
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            message = f"{prefix} ({root}): {detail(error)}"
            failures.append(message)
            if (prefix / "include/onnxruntime_c_api.h").exists():
                print("Not usable: " + message, flush=True)
            return None

    if requested and (not devices or driver_version < requested * 1000):
        raise ValueError(f"CUDA {requested} requires a working compatible NVIDIA driver. Verify nvidia-smi; see {CUDA_DOC}")
    if requested == 13 and any(capability < 7.5 for _, _, capability in devices):
        raise ValueError("CUDA 13 does not support every visible GPU; use --cuda=12 or select CUDA_VISIBLE_DEVICES")
    if args.mode != "cpu" and devices:
        for prefix in prefixes:
            for root in roots:
                result = attempt(prefix, root, True)
                if result:
                    break
            else:
                continue
            break
        else:
            result = None
        if result:
            if result["cuda_major"] == 12 and driver_version >= 13000 and all(d[2] >= 7.5 for d in devices):
                print("Keeping the working CUDA 12 installation. CUDA 13 is optional: ./init_scalpel3.sh --cuda=13")
            return result

        # Reuse installed CUDA libraries with the matching official ONNX archive.
        if not args.check:
            for root in roots:
                for major in runtime_majors(root):
                    if requested and requested != major:
                        continue
                    try:
                        prefix = download_ort(base, args.version, major)
                    except (OSError, ValueError, urllib.error.URLError,
                            subprocess.SubprocessError) as error:
                        failures.append(detail(error))
                        print("Could not obtain matching ONNX libraries: " + detail(error), flush=True)
                        if requested:
                            raise
                        continue
                    result = attempt(prefix, root, True)
                    if result:
                        return result
            if requested:
                prefix = download_ort(base, args.version, requested)
                root = install_cuda(base, requested, devices)
                result = attempt(prefix, root, True)
                if result:
                    return result
                raise ValueError("The private CUDA installation failed inference; existing installations were left untouched")

    if requested:
        raise ValueError("Requested CUDA configuration did not pass. No CPU fallback.\n" + "\n".join(failures))
    print("\nGPU ACCELERATION IS OFF for this installation.")
    if args.mode != "cpu":
        if present and not devices:
            print("NVIDIA hardware is present but no usable device is visible. Check nvidia-smi and CUDA_VISIBLE_DEVICES.")
        elif devices:
            print("No compatible CUDA/ONNX installation passed inference. Diagnostics are listed above.")
        else:
            print("No usable NVIDIA GPU was detected.")
        if devices:
            recommended = 13 if driver_version >= 13000 and all(d[2] >= 7.5 for d in devices) else 12
            print(f"To install isolated libraries: ./init_scalpel3.sh --cuda={recommended}")
        print(f"Driver installation: {CUDA_DOC}\nONNX compatibility: {ORT_DOC}")
    print("For CPU execution, explicitly use Scalpel3 -Y cpu (and TESTS/cmdline.test -Y cpu).")
    for prefix in prefixes:
        result = attempt(prefix, "system", False)
        if result:
            # Do not let the ignored legacy private tree influence this build later.
            result["runtime"] = "system"
            result["failures"] = failures
            return result
    if args.check:
        raise ValueError("No installed ONNX Runtime passed the CPU check either")
    prefix = download_ort(base, args.version, 0)
    result = attempt(prefix, "system", False)
    if not result:
        raise ValueError("The CPU ONNX installation failed inference")
    result["failures"] = failures
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=MODES, default="auto")
    parser.add_argument("--version", default="1.26.0")
    parser.add_argument("--check", action="store_true", help="No downloads or configuration changes")
    parser.add_argument("--output", type=Path, default=SOURCE.parent / ".scalpel3_onnx.conf")
    parser.add_argument("--base", type=Path,
                        default=Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "scalpel3/runtime")
    args = parser.parse_args(argv)
    if platform.system() != "Linux":
        parser.error("This helper is for Linux; macOS uses init_scalpel3.sh's existing installation path")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        parser.error("Invalid ONNX version")
    for command in ("cc", "c++", "readelf"):
        if not shutil.which(command):
            parser.error(f"{command} is required; run the full init_scalpel3.sh to install build prerequisites")
    base = args.base.expanduser().resolve()
    # Build flags in Autoconf/Make cannot safely carry arbitrary whitespace or commas.
    try:
        build_path(base)
    except ValueError as error:
        parser.error(str(error))
    try:
        if not args.check:
            base.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="scalpel3-onnx-check-") as work:
            # Downloads and installs are serialized across checkouts using this user's tree.
            if args.check:
                result = select(args, base, Path(work))
            else:
                with (base / ".install.lock").open("a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    result = select(args, base, Path(work))
                    with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent,
                                                     prefix=".onnx-config-", delete=False) as out:
                        temporary = Path(out.name)
                        json.dump(result, out, indent=2)
                        out.write("\n")
                    os.replace(temporary, args.output)
        print(f"ONNX configuration: {result['provider'].upper()}, {result['version']}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("ERROR: " + detail(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
