"""Generate Enigma Virtual Box 11.30 cases on Windows x64/WOW64.

Official download: https://www.enigmaprotector.com/assets/files/enigmavb.exe
Extract it without installing, using https://constexpr.org/innoextract/ :
  innoextract -e -d extracted enigmavb.exe
Copy only app/enigmavbconsole.exe into tools/11.30/bin. No runtime DLL is needed.
The console banner says 11.30 Build 20250428; setup metadata says Build 20250429.
No source build is available. The public installer and GUI are not retained.

  python packers/enigma-virtual-box/generate.py --output C:/Temp/evb-new
  python packers/enigma-virtual-box/generate.py --verify-only
  enigmavbconsole.exe project.evb

project.py creates explicit settings: embedded-file virtualization, optional
compression; no registry/storage, temporary mapping, virtual EXE launch or child
sharing. The plain four-way matrix uses no embedded files. All inputs unchanged.
The bundle cases reuse ../molebox/bundle/bundle.c with the adjacent CMake project:
  cmake -S packers/enigma-virtual-box/bundle -B C:/Temp/evb-build -G "Visual Studio 17 2022" -A x64 -DCMAKE_SYSTEM_VERSION=10.0.26100.0
  cmake --build C:/Temp/evb-build --config Release
Use -A Win32 for x86. VS 2022 v143 and SDK 10.0.26100.0 are used here.

The adapter wraps unchanged shared EXE/secrets code, loads a byte-identical shared
DLL by name, verifies callbacks by their original ordinals, and validates DATA
below via Win32 file reads. --wait enters the EXE loop; --dll-wait enters the DLL
loop. Missing DLL and corrupt data fail before packing. Bundles are checked alone
in a fresh directory and with corrupt external namesakes. Runtime checks cover
all EXE/DLL secrets, both loops, data and no files left beside the EXE. They are
not a system-wide disk-write trace. Main-PE markers remain visible in both modes;
stored embedded bytes are visible, compressed embedded DLL/data are not verbatim.

Only passing output PEs are published. Build/project files remain temporary.
All runtime tests use one-process jobs; CMake permits bounded build children.
"""
import argparse
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
sys.dont_write_bytecode = True
PACKER = Path(__file__).resolve().parent
ROOT = PACKER.parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
CHECK = load('checks', ROOT / 'tools/fixture_checks.py')
PROJECT = load('evb_project', PACKER / 'project.py')
TOOL = PACKER / 'tools/11.30/bin/enigmavbconsole.exe'
TOOL_HASH = 'f9be58dea8b070357c4b0b9e5d0caa85fc18842357a5e19f7b2810e22d1ec1b3'
# Same payload checked by the reused bundle entry; its original case name is intentional.
DATA = b'pe-fixture:molebox:virtual-data:v1\n' + bytes(range(256)) * 16
EXPECTED = 'pe-fixture:basic-dll:ok\npe-fixture:basic-exe:ok'


def check_run(path, code=0, output=None):
    result = CHECK.run([path], path.parent, 10)
    CHECK.require(result.returncode == code and not result.stderr,
                  f'Bundle failed: exit={result.returncode:#x}, stdout={result.stdout!r}, stderr={result.stderr!r}')
    if output is not None:
        CHECK.require(result.stdout.replace(b'\r\n', b'\n') == output, 'Unexpected bundle output')


def check_bundle(path, arch):
    before = path.read_bytes(); info = CHECK.PE.inspect_pe(path)
    _, ref = CHECK.reference(arch, 'exe')
    CHECK.require(info['machine'] == ref['pe']['machine'] and info['kind'] == 'EXE', 'Invalid bundle PE')
    check_run(path, output=(EXPECTED + '\n').encode())
    CHECK.WAIT.check_wait(path, '--wait', EXPECTED, path.parent)
    CHECK.WAIT.check_wait(path, '--dll-wait', 'pe-fixture:basic-dll:ok', path.parent)
    CHECK.require(path.read_bytes() == before, 'Bundle changed on execution')
    CHECK.require(all(bytes.fromhex(s['hex']) in before for s in ref['secrets']), 'Main-PE markers changed')
    print(f'{arch}/{path.name}: PASS EXE/DLL secret checks, data, both waits; main-PE markers visible', flush=True)


def isolated_bundle(path, arch, compressed, directory):
    directory.mkdir(); sample = directory / path.name; shutil.copyfile(path, sample)
    dll, _ = CHECK.reference(arch, 'dll'); data = sample.read_bytes()
    CHECK.require((DATA in data) == (not compressed) and (dll.read_bytes() in data) == (not compressed),
                  'Unexpected embedded-file visibility')
    check_bundle(sample, arch)
    CHECK.require(list(directory.iterdir()) == [sample], 'Bundle left files beside its EXE')
    (directory / 'fixture-bundle.dll').write_bytes(b'Invalid external DLL')
    (directory / 'fixture-data.bin').write_bytes(b'Invalid external data')
    check_bundle(sample, arch)
    CHECK.require((directory / 'fixture-bundle.dll').read_bytes() == b'Invalid external DLL'
                  and (directory / 'fixture-data.bin').read_bytes() == b'Invalid external data',
                  'External namesakes were modified')


def pack(source, output, compressed=False, extras=()):
    project = PROJECT.write(source, output, compressed, extras)
    result = CHECK.run([TOOL, project], output.parent, 30)
    CHECK.require(result.returncode == 0 and not result.stderr and b'File successfully saved' in result.stdout
                  and output.exists() and output.read_bytes() != source.read_bytes(),
                  'Packing failed: ' + repr(result.stdout))


def build(command, work):
    result = CHECK.run(command, work, 180, max_processes=16)
    CHECK.require(result.returncode == 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    CHECK.require(CHECK.sha256(TOOL) == TOOL_HASH, 'Unexpected tool')
    output = (args.output or PACKER / 'packed-fixtures/11.30').resolve(); saved = {}
    with tempfile.TemporaryDirectory(prefix='pe-enigmavb-') as temp:
        work = Path(temp)
        for arch, platform in [('x86', 'Win32'), ('amd64', 'x64')]:
            for kind in ('exe', 'dll'):
                source, _ = CHECK.reference(arch, kind)
                target = output / f'fixture-{arch}-{kind}/default.{kind}'
                if args.verify_only:
                    CHECK.verify(target, arch, kind); continue
                CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
                sample = work / f'{arch}-default.{kind}'
                pack(source, sample); CHECK.verify(sample, arch, kind); saved[target] = sample.read_bytes()
                CHECK.reference(arch, kind)
            if not args.verify_only:
                directory = work / f'build-{arch}'
                build(['cmake', '-S', PACKER / 'bundle', '-B', directory, '-G', 'Visual Studio 17 2022',
                       '-A', platform, '-DCMAKE_SYSTEM_VERSION=10.0.26100.0'], work)
                build(['cmake', '--build', directory, '--config', 'Release'], work)
                bundle = directory / 'Release/bundle.exe'; dll, _ = CHECK.reference(arch, 'dll')
                shutil.copyfile(dll, bundle.parent / 'fixture-bundle.dll')
                (bundle.parent / 'fixture-data.bin').write_bytes(DATA); check_bundle(bundle, arch)
                negative = work / f'missing-{arch}'; negative.mkdir(); shutil.copyfile(bundle, negative / 'bundle.exe')
                check_run(negative / 'bundle.exe', code=10, output=b'')
                shutil.copyfile(dll, negative / 'fixture-bundle.dll'); (negative / 'fixture-data.bin').write_bytes(b'Corrupt')
                check_run(negative / 'bundle.exe', code=11, output=b'')
            for compressed, profile in [(False, 'store'), (True, 'compressed')]:
                target = output / f'fixture-{arch}-exe/bundle-{profile}.exe'
                if args.verify_only:
                    isolated_bundle(target, arch, compressed, work / f'{arch}-{profile}'); continue
                CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
                sample = work / f'{arch}-bundle-{profile}.exe'
                pack(bundle, sample, compressed, [bundle.parent / 'fixture-bundle.dll', bundle.parent / 'fixture-data.bin'])
                isolated_bundle(sample, arch, compressed, work / f'{arch}-{profile}'); saved[target] = sample.read_bytes()
            CHECK.reference(arch, 'exe'); CHECK.reference(arch, 'dll')
        for target, data in saved.items():
            CHECK.publish(data, target)


if __name__ == '__main__':
    main()
