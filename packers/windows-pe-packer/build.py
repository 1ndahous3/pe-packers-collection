"""Build Windows PE Packer from pinned public sources with MSVC/MASM.

  python packers/windows-pe-packer/build.py --output C:/Temp/PE-Packer.exe

Requires Python, CMake, VS 2022 v143 x86 C tools/MASM and SDK 10.0.26100.0.
Source: https://github.com/czs108/Windows-PE-Packer
Commit: 8cce60ac258c75b89c2c5f57745d8914f2ecb21e
MASM32 includes: https://github.com/tonado/MASM32-SDK
Commit: 2bf70b217d0b12823a223503736d5da5e1dbd010
The original README uses i686 MinGW plus MASM32; that toolchain was not rebuilt.
This alternative builds the original packing/loader logic with these adaptations:
- make the absolute MASM32 include path local;
- simplify an unused COMP_ELEM_ALL forward expression to its numeric sum, and
  use parentheses in two old WCHAR array declarations for current MASM;
- force-include windows.h/shellapi.h for CommandLineToArgvW and link shell32;
- use static C runtime and /SAFESEH:NO for the packer executable's ASM object.
These are build compatibility changes, not a patch to the packing algorithm.
The shared fixture's flags are not affected by the packer build's link options.

Archives, headers, sources and intermediates are temporary. Retain only the built
EXE; source and dependencies remain available through pinned public links.
The build is not asserted byte-reproducible across timestamps or toolchain versions.
"""
import argparse
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import sys
import tempfile
import urllib.request
import zipfile
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('checks', ROOT / 'tools/fixture_checks.py')
CHECK = importlib.util.module_from_spec(spec); spec.loader.exec_module(CHECK)
COMMIT = '8cce60ac258c75b89c2c5f57745d8914f2ecb21e'
SDK_COMMIT = '2bf70b217d0b12823a223503736d5da5e1dbd010'
HEADERS = {
    'windows.inc': '0ad94d320de71cf675715c30fe4a53189b6f29806302c0ce55a384e3b56b4846',
    'winextra.inc': '1cdc28fa533bfef785fcec684c2ac11b1928099932dd4f162a76924e68b52754',
}


def download(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read()


def command(args, cwd):
    result = CHECK.run(args, cwd, 180, max_processes=16)
    CHECK.require(result.returncode == 0, result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(); output = args.output.resolve()
    CHECK.require(not output.exists(), 'Choose a fresh output file')
    with tempfile.TemporaryDirectory(prefix='pe-czs-build-') as temp:
        work = Path(temp)
        data = download(f'https://codeload.github.com/czs108/Windows-PE-Packer/zip/{COMMIT}')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                CHECK.require((work / name).resolve().is_relative_to(work), 'Unsafe archive path')
            archive.extractall(work)
        source = work / ('Windows-PE-Packer-' + COMMIT)
        includes = work / 'includes'; includes.mkdir()
        for name, digest in HEADERS.items():
            data = download(f'https://raw.githubusercontent.com/tonado/MASM32-SDK/{SDK_COMMIT}/include/{name}')
            CHECK.require(hashlib.sha256(data).hexdigest() == digest, 'Unexpected SDK include: ' + name)
            if name == 'windows.inc':
                data, count = re.subn(rb'^COMP_ELEM_ALL equ [^\r\n]+', b'COMP_ELEM_ALL equ 07dfh', data, flags=re.M)
                CHECK.require(count == 1, 'SDK alias not found')
            else:
                for old, new in [(b'WCHAR  [EVLEN + 1]', b'WCHAR  (EVLEN + 1)'),
                                 (b'WCHAR [SNLEN + 1]', b'WCHAR (SNLEN + 1)')]:
                    CHECK.require(data.count(old) == 1, 'SDK array declaration not found')
                    data = data.replace(old, new)
            (includes / name).write_bytes(data)
        asm = source / 'src/shell/entry_x86.asm'; text = asm.read_text(encoding='utf-8')
        CHECK.require(text.count('include /masm32/include/windows.inc') == 1, 'Unexpected ASM include')
        asm.write_text(text.replace('include /masm32/include/windows.inc', 'include windows.inc'), encoding='utf-8')
        compat = work / 'compat.h'; compat.write_text('#include <windows.h>\n#include <shellapi.h>\n')
        cmake = source / 'CMakeLists.txt'
        cmake.write_text(cmake.read_text(encoding='utf-8') + f'\n'
            'set_property(TARGET PE-Packer utility shell PROPERTY MSVC_RUNTIME_LIBRARY MultiThreaded)\n'
            f'target_compile_options(PE-Packer PRIVATE /FI"{compat.as_posix()}")\n'
            'target_link_libraries(PE-Packer PRIVATE shell32)\n'
            'target_link_options(PE-Packer PRIVATE /SAFESEH:NO)\n'
            f'target_include_directories(shell PRIVATE "{includes.as_posix()}")\n', encoding='utf-8')
        build = work / 'build'
        print('Building pinned source with MSVC/MASM compatibility settings...', flush=True)
        command(['cmake', '-S', source, '-B', build, '-G', 'Visual Studio 17 2022', '-A', 'Win32',
                 '-DCMAKE_SYSTEM_VERSION=10.0.26100.0'], work)
        command(['cmake', '--build', build, '--config', 'Release', '--target', 'PE-Packer'], work)
        binary = build / 'bin/Release/PE-Packer.exe'
        result = CHECK.run([binary], work, 10)
        CHECK.require(result.returncode == 0 and b'Usage: PE-Packer' in result.stdout and not result.stderr,
                      'Built tool failed its usage check')
        CHECK.publish(binary.read_bytes(), output)
        print(f'Built {output}; SHA-256 {CHECK.sha256(output)}', flush=True)


if __name__ == '__main__':
    main()
