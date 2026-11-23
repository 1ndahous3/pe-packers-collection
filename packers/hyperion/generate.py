"""Build the pinned upstream release in a temporary directory and test the shared PE matrix.

Run generation from an x86 MSVC developer prompt on Windows. --verify-only
uses the retained EXEs directly and needs only Python. Each generated case
uses two candidate runtime keys to keep startup within the fixture timeouts.
"""
import argparse
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZipFile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import fixture_checks as checks

RELEASES = {
    "dcc5ad11996885c10c0a9588e4df223e667c738a295d0a61e2f92d2b9cd3989b": "1.1",
    "546bba6c21a8e53a0ebd1b8665fdb96452b6cab6ffbd9956b7c34f8bdab5e518": "2.3.1",
}


def build(root, version):
    src = root / "Src"
    flags = ["/EHsc"] if version == "1.1" else ["/std:c11", "/ISrc/Payloads/Aes/c"]
    files = sorted((src / "Crypter").glob("*.cpp" if version == "1.1" else "*.c"))
    if version != "1.1":
        files.extend(sorted((src / "Payloads/Aes/c").glob("*.c")))
    # The newer release has two translation units named aes.c.
    objects = []
    for index, source in enumerate(files):
        obj = f"module-{index}.obj"
        subprocess.run(["cl", "/nologo", "/c", "/O2", "/MT", "/D_CRT_SECURE_NO_WARNINGS",
                        *flags, f"/Fo{obj}", source.relative_to(root)],
                       cwd=root, check=True, timeout=60)
        objects.append(obj)
    subprocess.run(["link", "/nologo", "/out:hyperion.exe", *objects],
                   cwd=root, check=True, timeout=60)
    tool = root / "hyperion.exe"
    checks.require(checks.PE.inspect_pe(tool)["machine"] == "0x014c",
                   "Use the x86 Native Tools Command Prompt for Visual Studio")
    return tool


def case_path(output, version, arch):
    return output / version / f"fixture-{arch}-exe" / "packed.exe"


def verify(path, arch):
    _, ref = checks.reference(arch, "exe")
    data = path.read_bytes()
    checks.require(all(bytes.fromhex(m["hex"]) not in data for m in ref["secrets"]),
                   f"{path}: found a complete plaintext marker")
    checks.verify(path, arch, "exe")


def generate(archive, output):
    data = archive.read_bytes()
    version = RELEASES.get(hashlib.sha256(data).hexdigest())
    checks.require(version is not None, "Expected the official Hyperion 1.1 or 2.3.1 ZIP")
    checks.require(shutil.which("cl") and shutil.which("link"), "Use an x86 MSVC developer prompt")
    with tempfile.TemporaryDirectory(prefix="hyperion-") as temp:
        root = Path(temp) / f"Hyperion-{version}"
        with ZipFile(io.BytesIO(data)) as release:
            release.extractall(temp)
        tool = build(root, version)
        results = {}
        for arch in ("x86", "amd64"):
            for kind in ("exe", "dll"):
                original, ref = checks.reference(arch, kind)
                source = root / f"fixture-{arch}.{kind}"
                packed = root / f"packed-{arch}.{kind}"
                shutil.copyfile(original, source)
                run = checks.run([tool, "-k", "1", "-s", "2", source.name, packed.name],
                                 root, timeout=30, max_processes=2)
                checks.require(checks.sha256(source) == ref["sha256"], "Input changed during packing")
                if kind == "dll" or (arch == "amd64" and version == "1.1"):
                    reason = b"file is a dll" if kind == "dll" else b"file is pe64"
                    checks.require(run.returncode != 0 and reason in run.stderr.lower()
                                   and not packed.exists(), f"Unexpected outcome for {source.name}")
                    print(f"{source.name}: rejected ({reason.decode()})")
                    continue
                checks.require(run.returncode == 0 and packed.is_file(),
                               f"Packing {source.name} failed: {run.stderr!r}")
                verify(packed, arch)
                results[case_path(output, version, arch)] = packed.read_bytes()
        for path, content in results.items():
            checks.require(not path.exists() or path.read_bytes() == content,
                           f"Existing file differs: {path}. Use a fresh output directory.")
        for path, content in results.items():
            checks.publish(content, path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--archive", type=Path, help="official release ZIP to test")
    mode.add_argument("--verify-only", action="store_true", help="check the retained fixtures")
    parser.add_argument("--output", type=Path, help="parent of generated version directories")
    args = parser.parse_args()
    if args.verify_only:
        if args.output is not None:
            parser.error("--output is only used with --archive")
        for version, arch in (("1.1", "x86"), ("2.3.1", "x86"), ("2.3.1", "amd64")):
            verify(case_path(HERE / "packed-fixtures", version, arch), arch)
    elif args.output is None:
        parser.error("--archive requires --output")
    else:
        generate(args.archive, args.output)


if __name__ == "__main__":
    main()
