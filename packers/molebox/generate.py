"""Generate and verify MoleBox 4.6000 fixtures on Windows x64/WOW64.

Acquisition:
  https://github.com/sudachen/Molebox/releases/download/6000/molebox_gpl.zip
Retain MxbPack.exe, zlib_32r10.dll and libhash_32r10.dll from Molebox_GPL.
The GUI and its dependencies are unnecessary for this CLI workflow.

The adjacent x86 msvcr100.dll 10.00.40219.1 comes from Microsoft's VC++ 2010 SP1
redistributable, not from the MoleBox ZIP:
  https://www.microsoft.com/en-us/download/details.aspx?id=26999
  https://download.microsoft.com/download/1/6/5/165255e7-1014-4d0a-b094-b6a430a6bffc/vcredist_x86.exe
Extract vc_red.cab with 7-Zip, then F_CENTRAL_msvcr100_x86; rename to msvcr100.dll.
No installer execution is required. Archives/build intermediates are not kept.

Source tag 6000: 57821f1ba998603e9bfd5d8ce194a6ae2e8a3516
  https://github.com/sudachen/Molebox/tree/6000
Upstream build: VS 2010, C:/Python27, clone sudachen/xternal inside Molebox,
then makeall.cmd. We use the official binary and did not reproduce that build.

Usage from repository root:
  python packers/molebox/generate.py --output C:/Temp/molebox-new
  python packers/molebox/generate.py --verify-only
  python packers/molebox/generate.py --probe-failed --output C:/Temp/molebox-probes
The bundle adapter needs CMake, VS 2022 v143 and SDK 10.0.26100.0. Ordinary
fixtures and verification need only the retained tool/runtime and Python.

Packing commands (run in the input directory):
  MxbPack.exe fixture.exe -o packed.exe --autoreg none -C 0
  MxbPack.exe fixture.exe -o stored.exe --autoreg none -C 0 -s
  MxbPack.exe bundle.exe -o bundled.exe --autoreg none -C 0 \
      "fixture-bundle.dll;fixture-bundle.dll" "fixture-data.bin;fixture-data.bin"
Add -s to the bundle command for the whole-EXE storage profile. Slicing is the
implicit default: advertised -z is rejected in this release. --autoreg none
avoids COM registration during packing; -C 0 prefers embedded files.

The shared EXE is packed unchanged. The extra CMake entry wraps unchanged
basic_exe.c/secrets.c, dynamically loads a byte-identical shared x86 DLL and
checks deterministic data through ordinary Win32 file APIs. The payload is
DATA below; bundle.c checks its length and FNV-1a checksum. Normal execution
prints DLL then EXE success lines. --wait reaches the shared EXE sleep loop;
--dll-wait reaches the embedded DLL's WaitFixture. Both callbacks are resolved
by name and checked against their original ordinals. Missing DLL and corrupted
data negative controls must fail before packing. Packed bundles are tested
alone in a fresh directory and again with invalid external namesakes.

Every fixture run uses a one-process kill-on-close Windows job. Only the CMake
build allows bounded children. --probe-failed also checks direct DLL rejection,
the invalid amd64 result and the advertised-but-rejected -z switch. No input
patches, failed outputs, unpacked copies, reports or dependencies of generated
bundles are retained. Use a fresh output directory; packing is not asserted to
be byte-deterministic.
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
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
TOOL_DIR = PACKER / 'tools/4.6000/bin'
TOOL = TOOL_DIR / 'MxbPack.exe'
HASHES = {
    'MxbPack.exe': 'a4da2297d2bb52fa343d86be9c3c4f2871bd3da644cebcebb994baac7b1d607d',
    'libhash_32r10.dll': '8760f1a97a6ad86f88dc30b778e2742192bae2fcef4b6edacabc17edca174d8f',
    'zlib_32r10.dll': '04d782484f1fce948ccffd9c4d04150beb21c28e1ef6884f7ac21e69482d01ab',
    'msvcr100.dll': '60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa',
}
DATA = b'pe-fixture:molebox:virtual-data:v1\n' + bytes(range(256)) * 16
EXPECTED = 'pe-fixture:basic-dll:ok\npe-fixture:basic-exe:ok'
PROFILES = {'default': [], 'store': ['-s']}


def check_run(path, expected=0, output=None):
    result = CHECK.run([path], path.parent, 10)
    CHECK.require(result.returncode == expected and not result.stderr,
                  f'Bundle exit={result.returncode:#x}; stdout={result.stdout!r}; stderr={result.stderr!r}')
    if output is not None:
        CHECK.require(result.stdout.replace(b'\r\n', b'\n') == output, 'Unexpected bundle output')


def check_bundle(path, packed):
    before = path.read_bytes()
    info = CHECK.PE.inspect_pe(path)
    CHECK.require(info['machine'] == '0x014c' and info['kind'] == 'EXE', 'Invalid bundle PE')
    check_run(path, output=(EXPECTED + '\n').encode())
    CHECK.WAIT.check_wait(path, '--wait', EXPECTED, path.parent)
    CHECK.WAIT.check_wait(path, '--dll-wait', 'pe-fixture:basic-dll:ok', path.parent)
    CHECK.require(path.read_bytes() == before, 'Bundle changed on execution')
    visible = []
    for kind in ('exe', 'dll'):
        _, ref = CHECK.reference('x86', kind)
        visible += [f'{kind}:{m["id"]}' for m in ref['secrets'] if bytes.fromhex(m['hex']) in before]
    if packed:
        CHECK.require(not visible and DATA not in before, 'Complete bundle marker visible')
    print(f'{path.name}: PASS bundle EXE/DLL secrets, data, both waits; '
          f'full disk markers={visible}; ASLR={info["dynamic_base"]}, DEP={info["nx_compatible"]}', flush=True)


def isolated_bundle(path, work):
    work.mkdir()
    isolated = work / path.name
    shutil.copyfile(path, isolated)
    check_bundle(isolated, packed=True)
    CHECK.require(list(work.iterdir()) == [isolated], 'Bundle left files beside its EXE')
    (work / 'fixture-bundle.dll').write_bytes(b'Invalid external DLL')
    (work / 'fixture-data.bin').write_bytes(b'Invalid external data')
    check_bundle(isolated, packed=True)
    print('PASS embedded files take precedence over invalid external namesakes', flush=True)


def build(command, work):
    result = CHECK.run(command, work, 180, max_processes=16)
    CHECK.require(result.returncode == 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))


def pack(source, output, options, extras=()):
    result = CHECK.run([TOOL, source, '-o', output, '--autoreg', 'none', '-C', '0'] + options + list(extras), source.parent, 30)
    CHECK.require(result.returncode == 0 and output.exists(),
                  result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))


def probe_failed(work):
    for arch, kind in (('x86', 'dll'), ('amd64', 'dll'), ('amd64', 'exe')):
        original, _ = CHECK.reference(arch, kind)
        target = work / f'failed-{arch}-{kind}.exe'
        result = CHECK.run([TOOL, original, '-o', target, '--autoreg', 'none'], work, 30)
        if kind == 'dll':
            CHECK.require(result.returncode != 0 and b'is not PE image' in result.stdout and not target.exists(),
                          'Unexpected direct DLL result')
        else:
            CHECK.require(result.returncode == 0 and b'treating as .NET' in result.stdout and
                          CHECK.PE.inspect_pe(target)['machine'] == '0x014c', 'Unexpected amd64 result')
            try:
                CHECK.run([target], work, 5)
            except OSError as error:
                CHECK.require(error.winerror == 193, f'Unexpected loader error: {error}')
            else:
                raise ValueError('The unsupported amd64 output was unexpectedly executable')
    original, _ = CHECK.reference('x86', 'exe')
    result = CHECK.run([TOOL, original, '-o', work / 'invalid-z.exe', '-z'], work, 15)
    CHECK.require(result.returncode != 0 and b"invalid option '-z'" in result.stdout, 'Unexpected -z behavior')
    print('PASS direct DLL, amd64 and -z negative probes', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--probe-failed', action='store_true')
    args = parser.parse_args()
    for name, digest in HASHES.items():
        CHECK.require(CHECK.sha256(TOOL_DIR / name) == digest, f'Unexpected tool dependency: {name}')
    target = (args.output or PACKER / 'packed-fixtures/4.6000').resolve() / 'fixture-x86-exe'
    original, _ = CHECK.reference('x86', 'exe')
    dll, _ = CHECK.reference('x86', 'dll')
    with tempfile.TemporaryDirectory(prefix='pe-molebox-') as temp:
        work = Path(temp)
        if args.verify_only:
            for profile in PROFILES:
                CHECK.verify(target / f'{profile}.exe', 'x86', 'exe')
                isolated_bundle(target / f'bundle-{profile}.exe', work / profile)
            return
        CHECK.require(not target.exists(), 'Use --verify-only or a fresh --output')
        source_hashes = {p: CHECK.sha256(p) for p in (ROOT / 'fixtures/src').iterdir() if p.is_file()}
        directory = work / 'build'
        build(['cmake', '-S', PACKER / 'bundle', '-B', directory, '-G', 'Visual Studio 17 2022',
               '-A', 'Win32', '-DCMAKE_SYSTEM_VERSION=10.0.26100.0'], work)
        build(['cmake', '--build', directory, '--config', 'Release'], work)
        bundle = directory / 'Release/bundle.exe'
        shutil.copyfile(dll, bundle.parent / 'fixture-bundle.dll')
        (bundle.parent / 'fixture-data.bin').write_bytes(DATA)
        check_bundle(bundle, packed=False)
        negative = work / 'missing'; negative.mkdir()
        shutil.copyfile(bundle, negative / 'bundle.exe')
        check_run(negative / 'bundle.exe', expected=10, output=b'')
        shutil.copyfile(dll, negative / 'fixture-bundle.dll')
        (negative / 'fixture-data.bin').write_bytes(b'Corrupt data')
        check_run(negative / 'bundle.exe', expected=11, output=b'')
        print('PASS missing DLL and corrupt data baseline controls', flush=True)
        extras = [str(bundle.parent / name) + ';' + name for name in ('fixture-bundle.dll', 'fixture-data.bin')]
        outputs = {}
        for profile, options in PROFILES.items():
            plain = work / f'{profile}.exe'
            pack(original, plain, options)
            CHECK.verify(plain, 'x86', 'exe')
            outputs[plain.name] = plain.read_bytes()
            bundled = work / f'bundle-{profile}.exe'
            pack(bundle, bundled, options, extras)
            isolated_bundle(bundled, work / profile)
            outputs[bundled.name] = bundled.read_bytes()
        if args.probe_failed:
            probe_failed(work)
        CHECK.require(all(CHECK.sha256(p) == h for p, h in source_hashes.items()), 'Shared source changed')
        CHECK.reference('x86', 'exe'); CHECK.reference('x86', 'dll')
        for name, data in outputs.items():
            CHECK.publish(data, target / name)


if __name__ == '__main__':
    main()
