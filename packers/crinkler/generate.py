"""Build Crinkler 3.0b fixtures from the shared C sources.

Download https://github.com/runestubbe/Crinkler/releases/download/v3.0b/crinkler30b.zip
Keep Win64/Crinkler.exe in tools/3.0b/bin. Host bitness does not change the x86
output target. Sources: https://github.com/runestubbe/Crinkler/tree/v3.0b ; the
upstream source build was not reproduced. Only the official binary is retained.

Requires Windows x64/WOW64, SSE4.2, CMake, VS 2022 v143 and SDK 10.0.26100.0.
  python packers/crinkler/generate.py
  python packers/crinkler/generate.py --verify-only
  python packers/crinkler/generate.py --probe-failed --output C:/Temp/crinkler-new

The adapter CMakeLists compiles unchanged basic_exe.c/secrets.c with baseline
/Od /Ob0 /GS- /Zl /Oi- options. It links a temporary normal PE and a compressed PE
from the SAME objects. Both pass runtime/wait/secret checks. This is a source-
derived case, not compression of the published basic.exe bytes.

Crinkler options: /ENTRY:FixtureEntry /NODEFAULTLIB /SUBSYSTEM:CONSOLE
/COMPMODE:FAST /HASHSIZE:32 plus both objects and SDK kernel32.lib/user32.lib.
/ENTRY expects the undecorated name, unlike Microsoft's stdcall entry syntax.
user32 is needed by Crinkler's import-error reporting stub. No TINYHEADER,
TINYIMPORT, code transform or output patch is used. The adapter can also be
configured manually with CRINKLER and SDK_LIB_DIR cache variables.

--probe-failed confirms that raw PEs are unsupported inputs and /DLL is ignored;
with valid objects it still produces an EXE. It also compiles x64 objects and
checks Crinkler's unsupported-file-type result. Failed/extra probe artifacts,
objects and normal linked inputs are temporary and never retained. A fresh
--output is required to regenerate. CMake gets a bounded job with room for its
build children; fixture executions each have a one-process job.
"""
import argparse
import importlib.util
from pathlib import Path
import sys
import tempfile
import winreg
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
HASH = '86e4d861105de24a9f599a5e7319e45d052c0dc2413bbe7a08fbd71ab5fb49d8'
SDK_VERSION = '10.0.26100.0'


def build(command, work):
    result = CHECK.run(command, work, timeout=180, max_processes=16)
    CHECK.require(result.returncode == 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    tool = PACKER / 'tools/3.0b/bin/Crinkler.exe'
    CHECK.require(CHECK.sha256(tool) == HASH, 'Unexpected Crinkler binary')
    target = (args.output or PACKER / 'packed-fixtures/3.0b').resolve() / 'fixture-x86-exe/fast.exe'
    CHECK.reference('x86', 'exe')
    if args.verify_only:
        CHECK.verify(target, 'x86', 'exe'); return
    CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows Kits\Installed Roots',
                        0, winreg.KEY_READ | winreg.KEY_WOW64_32KEY) as key:
        sdk = Path(winreg.QueryValueEx(key, 'KitsRoot10')[0]) / 'Lib' / SDK_VERSION / 'um/x86'
    source_paths = [ROOT / 'fixtures/src' / name for name in ('basic_exe.c', 'secrets.c', 'secrets.h')]
    hashes = {p: CHECK.sha256(p) for p in source_paths}
    with tempfile.TemporaryDirectory(prefix='pe-crinkler-') as temp:
        work = Path(temp); directory = work / 'build'
        build(['cmake', '-S', PACKER / 'adapter', '-B', directory, '-G', 'Visual Studio 17 2022',
               '-A', 'Win32', f'-DCMAKE_SYSTEM_VERSION={SDK_VERSION}', f'-DCRINKLER={tool}',
               f'-DSDK_LIB_DIR={sdk}'], work)
        build(['cmake', '--build', directory, '--config', 'Release'], work)
        baseline = directory / 'Release/baseline.exe'
        _, ref = CHECK.reference('x86', 'exe')
        CHECK.require(all(bytes.fromhex(m['hex']) in baseline.read_bytes() for m in ref['secrets']),
                      'Normal source build lost a complete marker')
        CHECK.verify(baseline, 'x86', 'exe')
        CHECK.verify(directory / 'packed.exe', 'x86', 'exe')
        if args.probe_failed:
            for arch in ('x86', 'amd64'):
                for kind in ('exe', 'dll'):
                    original, _ = CHECK.reference(arch, kind)
                    result = CHECK.run([tool, '/OUT:raw.bin', original], work, 15)
                    CHECK.require(result.returncode != 0 and b'Unsupported file type' in result.stdout,
                                  'Unexpected raw-PE probe result')
            objects = sorted((directory / 'fixture_objects.dir/Release').glob('*.obj'))
            command = [tool, '/OUT:dll-probe.exe', '/DLL', '/ENTRY:FixtureEntry', '/NODEFAULTLIB',
                       '/SUBSYSTEM:CONSOLE', '/COMPMODE:FAST', '/HASHSIZE:32'] + objects + [sdk / 'kernel32.lib', sdk / 'user32.lib']
            result = CHECK.run(command, work, 60)
            CHECK.require(result.returncode == 0 and b"Ignoring unknown argument '/DLL'" in result.stdout and
                          CHECK.PE.inspect_pe(work / 'dll-probe.exe')['kind'] == 'EXE', 'Unexpected /DLL behavior')
            amd = work / 'amd64'
            build(['cmake', '-S', ROOT / 'fixtures', '-B', amd, '-G', 'Visual Studio 17 2022',
                   '-A', 'x64', f'-DCMAKE_SYSTEM_VERSION={SDK_VERSION}'], work)
            build(['cmake', '--build', amd, '--config', 'Release', '--target', 'basic_exe'], work)
            objects64 = sorted((amd / 'basic_exe.dir/Release').glob('*.obj'))
            CHECK.require(len(objects64) == 2, 'Missing amd64 objects')
            result = CHECK.run([tool, '/OUT:amd64.bin'] + objects64, work, 15)
            CHECK.require(result.returncode != 0 and b'Unsupported file type' in result.stdout,
                          'Unexpected amd64 object result')
            print('PASS negative probes: raw PE, DLL switch, amd64 COFF')
        CHECK.require(all(CHECK.sha256(p) == h for p, h in hashes.items()), 'Shared source changed')
        CHECK.publish((directory / 'packed.exe').read_bytes(), target)


if __name__ == '__main__':
    main()
