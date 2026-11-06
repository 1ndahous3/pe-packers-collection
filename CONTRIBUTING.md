# Contributing

## Adding packers and cases

- Keep candidates in the [root index](README.md#packer-indexes), using its availability categories. Preserve names, references and existing directory paths when moving entries between categories.
- Create a packer directory when concrete research or testing starts. Use a lowercase ID with digits and hyphens, one directory per family or tool, and link it in the index's `Directory` column. Place entries with a directory link above entries without one. Follow the [template guide](templates/README.md) for layout, versions, retained files and README contents.
- Prefer official or other stable public downloads for packer tools. Extract from historical collections or disc images only when the required version is otherwise difficult to obtain.
- Generate cases from the [shared PE fixtures](fixtures/README.md#use-in-a-packer-case); that guide defines fixture mapping, input hashes, execution and secret checks. Do not silently overwrite a different artifact.
- Put reusable utilities in [tools](tools/README.md) and packer-specific helpers beside the packer's README. Keep useful source leads and identity/scope decisions in [sources.md](sources.md).

## Evidence and verification

Document relevant tool versions, settings, reproduction steps and observed behavior. Commands belong in helper documentation; the packer README summarizes results. Use optional `internals.md` for [technical research and reproduction notes](templates/README.md#research-notes). Distinguish a failed check, an unsupported case and a check that was not run.

Define what successful recovery means for the case: code, entry point, imports, data, secrets or execution behavior. Require byte-for-byte equality only when justified. A dump from another unpacker needs its own verification before it can serve as a reference.

For imported samples, record the original filename, source URL and archive member, architecture, EXE/DLL kind and packer attribution. Identify the payload as benign, malware or unknown; state whether an unpacked original or reproducible packing workflow exists. Keep import and execution separate; helpers must not execute imported samples automatically.

## Documentation

Use English and plain Markdown. Omit HTML layout, added/updated timestamps and case counters. Prefer official sites, repositories and manuals; detector labels alone do not establish an exact version or runtime behavior.

After changing documentation or moving files, run:

```text
python tools/check_links.py
```
