# Packer template guide

Copy [packer/](packer/) to `packers/<packer-id>/`. This guide stays in `templates/` and is not copied with the packer directory.

## Directory layout

```text
packers/<packer-id>/
  README.md
  internals.md              # Optional research notes
  packed-fixtures/
    <version>/
      fixture-amd64-dll/
      fixture-amd64-exe/
      fixture-x86-dll/
      fixture-x86-exe/
  packed-samples/
    <version>/
      <sample-name>/
  tools/
    <version>/
      bin/
      src/
```

`<version>` identifies the packer; use `0` when unknown. Use the same label across the three branches and create only the directories needed.

## File and directory purposes

- `README.md`: a short description, references and inventory of versions, fixtures and imported samples. Adapt the [README template](packer/README.md) to the available material.
- `packed-fixtures/`: packed PE files generated from the shared fixtures. Originals and manifests remain in the collection's `fixtures/` directory.
- `packed-samples/`: imported packed files, grouped by their actual sample names.
- `tools/<version>/bin/`: the packer executable and dependencies needed to run it.
- `tools/<version>/src/`: fallback sources when a stable public source is unavailable. Preserve rare distribution archives alongside `bin/` and `src/`; otherwise link the public download.

## Research notes

Optional `internals.md` explains mechanisms, observations, limitations, relevant differences between versions and how to reproduce experiments. Keep conclusions and reproduction steps here, without duplicating file inventories, hashes, sizes, case-specific RVAs, offsets or raw reports.

See [CONTRIBUTING](../CONTRIBUTING.md) for contribution and verification rules, and the [fixture instructions](../fixtures/README.md) for building inputs, running checks and using secrets.
