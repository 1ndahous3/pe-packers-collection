"""Build an EVB XML project; fields verified against the 11.30 GUI and console.

The GUI saves an unnamed root tag; the console also accepts a normal Project root.
Action 0 virtualizes each file without extracting it. Disable temporary mapping,
virtual EXE launch, child-process sharing, registry virtualization and storage.
CompressFiles applies to embedded files, not the main input PE.
"""
import xml.etree.ElementTree as ET


def write(source, output, compressed=False, extras=()):
    root = ET.Element('Project')
    def add(parent, name, text):
        ET.SubElement(parent, name).text = str(text)
    add(root, 'InputFile', source); add(root, 'OutputFile', output)
    files = ET.SubElement(root, 'Files')
    for name, value in [('Enabled', True), ('DeleteExtractedOnExit', False), ('CompressFiles', compressed)]:
        add(files, name, value)
    entries = ET.SubElement(files, 'Files')
    if extras:
        folder = ET.SubElement(entries, 'File')
        add(folder, 'Type', 3); add(folder, 'Name', '%DEFAULT FOLDER%'); add(folder, 'Action', 0)
        entries = ET.SubElement(folder, 'Files')
        for file in extras:
            item = ET.SubElement(entries, 'File')
            for name, value in [('Type', 2), ('Name', file.name), ('File', file), ('Action', 0),
                                ('ActiveX', False), ('ActiveXInstall', False)]:
                add(item, name, value)
    for name in ('Registries', 'Packaging'):
        add(ET.SubElement(root, name), 'Enabled', False)
    options = ET.SubElement(root, 'Options')
    for name in ('ShareVirtualSystem', 'MapExecutableWithTemporaryFile',
                 'AllowRunningOfVirtualExeFiles', 'ProcessesOfAnyPlatforms'):
        add(options, name, False)
    add(ET.SubElement(ET.SubElement(root, 'Storage'), 'Files'), 'Enabled', False)
    path = output.with_suffix('.evb')
    ET.ElementTree(root).write(path, encoding='utf-8', xml_declaration=True)
    return path
