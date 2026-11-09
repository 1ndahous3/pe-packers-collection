"""Generate PeX 0.99 fixtures (Windows, Python standard library).

The rare distribution is retained as tools/0.99/pex-0.99.rar. It contains pex.exe,
a WinHelp manual and src.RAR with MASM sources, resources and aplib.lib. Build
scripts use absolute E: paths and ml/link; they were inspected, not executed.
Do not run the bundled batch cleanup/copy steps blindly. Keep only pex.exe in bin.

Source: https://archive.org/details/cracklb-2010
SUN_2010.iso member ANALYZE_L@B/Protectors/PeX 0.99.rar.
Recovery range: bytes 1156345856-1156388828 (42973 bytes). Resolve a current
archive.org metadata storage host if the generic download URL fails; require
206, exact Content-Range/length, then verify the archive hash and run 7z t/x.
Archive SHA256: 90f170cc94ccd912eacb04364eabeffb15140d0710395311036eca2cb112657a

  python packers/pex/generate.py
  python packers/pex/generate.py --verify-only
  python packers/pex/generate.py --probe-failed --output C:/Temp/pex-new

Prepare a temporary EXE by clearing DYNAMIC_BASE, NO_SEH and NX_COMPAT (0x540).
Default: pex.exe fixture.exe
Minimal: pex.exe fixture.exe -R -I -X
-R retains relocations; -I disables import protection; -X disables BPX protection.
Alignment remains enabled in both. -A/-L DISABLE alignment and produced an invalid
output in our test; -B enables a backup and is not used. Options follow the file.
The CLI requires an .exe filename, even for negative DLL probes, and overwrites
that file. Use a short relative filename without spaces. CLI settings do not use
or update the GUI registry key. Successful and rejected runs BOTH return -1;
validate output changes and execution instead of treating that code as failure.

--probe-failed submits the three unsupported cells; require unchanged bytes.
Normal/wait/secret checks must pass before publication. Use a fresh --output for
regeneration; existing artifacts are never silently replaced. Outputs and shared
originals are not patched, and child processes use bounded one-process jobs.
"""
import argparse
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
HASH = 'f1b5d8ed667595921c92c12f115240f3b13959c9d643adf6b02c22c5e2de5dd0'
PROFILES = {'default': [], 'minimal': ['-R', '-I', '-X']}


def prepare(raw):
    data = bytearray(raw); nt = struct.unpack_from('<I', data, 60)[0]
    flags = struct.unpack_from('<H', data, nt + 94)[0]
    CHECK.require(flags & 0x540 == 0x540, 'Unexpected original flags')
    struct.pack_into('<H', data, nt + 94, flags & ~0x540)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    tool = PACKER / 'tools/0.99/bin/pex.exe'
    CHECK.require(CHECK.sha256(tool) == HASH, 'Unexpected PeX binary')
    output = (args.output or PACKER / 'packed-fixtures/0.99').resolve()
    for profile, switches in PROFILES.items():
        target = output / 'fixture-x86-exe' / f'{profile}-compatible.exe'
        if args.verify_only:
            CHECK.verify(target, 'x86', 'exe'); continue
        CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
        source, ref = CHECK.reference('x86', 'exe')
        with tempfile.TemporaryDirectory(prefix='pe-pex-') as temp:
            work = Path(temp); sample = work / 'fixture.exe'; before = prepare(source.read_bytes())
            sample.write_bytes(before)
            result = CHECK.run([tool, sample.name] + switches, work, 30)
            CHECK.require(result.returncode == 0xffffffff and sample.read_bytes() != before,
                          'PeX did not produce output')
            CHECK.verify(sample, 'x86', 'exe'); CHECK.publish(sample.read_bytes(), target)
        CHECK.require(CHECK.sha256(source) == ref['sha256'], 'Shared original changed')
    if args.probe_failed and not args.verify_only:
        for arch, kind in [('x86', 'dll'), ('amd64', 'exe'), ('amd64', 'dll')]:
            source, _ = CHECK.reference(arch, kind)
            with tempfile.TemporaryDirectory(prefix='pe-pex-') as temp:
                work = Path(temp); sample = work / 'fixture.exe'; before = source.read_bytes()
                sample.write_bytes(before)
                result = CHECK.run([tool, sample.name] + PROFILES['minimal'], work, 30)
                CHECK.require(result.returncode == 0xffffffff and sample.read_bytes() == before,
                              'Unexpected unsupported-input result')
                print(f'{arch}/{kind}: rejected, bytes unchanged')


if __name__ == '__main__':
    main()
