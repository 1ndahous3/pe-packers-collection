"""Shared checks for packer generators; Windows, Python standard library only.

Import this module with importlib.util. reference(arch, kind) verifies the shared
binary hash and all complete markers and returns (path, manifest_record).
verify(path, arch, kind) requires exact success output, exit zero, empty stderr,
matching PE architecture/kind/exports, wait readiness and liveness (DLL name and
ordinal 4). Success output covers all runtime marker checksums; full-marker
visibility in the on-disk packed bytes is reported separately. This does not
claim byte-exact memory recovery or reconstruction of the original disk PE.

run() and verify() contain children in one-process Windows jobs. publish() refuses
to replace different artifacts. This module does not acquire or execute imported
samples. Helpers may call command() for the same bounded fixture invocation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ISOLATED = load("fixture_process", "fixtures/scripts/isolated_process.py")
WAIT = load("fixture_wait", "fixtures/scripts/check_wait.py")
PE = load("fixture_pe", "fixtures/scripts/manifest.py")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reference(arch, kind):
    manifest = ROOT / "fixtures/bin" / arch / "manifest.json"
    ref = next(a for a in json.loads(manifest.read_text(encoding="utf-8"))["artifacts"]
               if a["id"] == f"basic-{kind}-{arch}")
    path = manifest.parent / ref["path"]
    require(sha256(path) == ref["sha256"], f"Shared fixture hash mismatch: {path}")
    require(all(bytes.fromhex(m["hex"]) in path.read_bytes() for m in ref["secrets"]),
            "Shared fixture marker missing")
    return path, ref


def run(command, cwd, timeout=30):
    return ISOLATED.run([str(x) for x in command], cwd=cwd, timeout=timeout,
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)


def command(path, arch, kind, entry="RunFixture"):
    path = Path(path).resolve()
    if kind == "exe":
        return [str(path)]
    windows = Path(os.environ["WINDIR"])
    native = "Sysnative" if (windows / "Sysnative/rundll32.exe").exists() else "System32"
    return [str(windows / ("SysWOW64" if arch == "x86" else native) / "rundll32.exe"),
            "./" + path.name + "," + entry]


def normal(path, arch, kind):
    result = run(command(path, arch, kind), Path(path).parent, 10)
    require(result.returncode == 0 and
            result.stdout.replace(b"\r\n", b"\n") == f"pe-fixture:basic-{kind}:ok\n".encode()
            and not result.stderr,
            f"Runtime failed: exit={result.returncode:#x}, stdout={result.stdout!r}, "
            f"stderr={result.stderr!r}")


def verify(path, arch, kind):
    path = Path(path).resolve()
    _, ref = reference(arch, kind)
    before = path.read_bytes()
    info = PE.inspect_pe(path)
    for field in ("machine", "optional_header", "kind", "exports"):
        require(info[field] == ref["pe"][field], f"Packed PE differs in {field}")
    normal(path, arch, kind)
    WAIT.check_fixture(path, arch, kind)
    require(path.read_bytes() == before, "Execution modified packed bytes")
    visible = [m["id"] for m in ref["secrets"] if bytes.fromhex(m["hex"]) in before]
    print(f"{path.name}: PASS normal/wait/secret checksums; full disk markers={visible}; "
          f"ASLR={info['dynamic_base']}, DEP={info['nx_compatible']}", flush=True)
    return info


def publish(data, path):
    path = Path(path)
    require(not path.exists() or path.read_bytes() == data,
            f"Refusing to overwrite different output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with path.open("xb") as stream:
            stream.write(data)
