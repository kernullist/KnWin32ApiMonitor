# CycloneDX 1.7 schemas

Unmodified JSON schemas and Apache-2.0 license from the official
[CycloneDX specification](https://github.com/CycloneDX/specification/tree/4b3f59453366e27c8073fd24e98bf21ef8892c8e),
tag `1.7`, commit `4b3f59453366e27c8073fd24e98bf21ef8892c8e`.

`SHA256SUMS.json` pins the downloaded bytes of all four schemas and the license.
The local validator verifies those hashes before compiling the schema. It uses
the repository's pinned Ajv dependency, without network schema resolution.
JSON Schema `format` annotations are not asserted by this structural check;
dependency identities, registry hashes, distribution URLs and graph relationships
are separately compared against the lockfiles and current Cargo resolution.

Upstream source URLs are formed from the pinned commit and `schema/<filename>`;
the license is the repository-root `LICENSE`. `jsf-0.82.schema.json` and
`cryptography-defs.schema.json` resolve references from `bom-1.7.schema.json`.
