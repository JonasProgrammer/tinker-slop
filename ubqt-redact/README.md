# ubqt-redact

Prepare Ubiquiti EdgeRouter boot configurations for sharing, then restore their
secret values into arbitrary text configurations. This tool redacts values; it
does not convert router configurations.

The JSON map contains original secrets in plaintext, including source spellings.
Keep it private and out of AI workflows, version control, tickets, and logs. Share
only the sanitized configuration after reviewing it locally. Detection is based
on configuration paths and obvious secret names; unrelated comments, identifying
information, and secrets in unrecognized fields can remain.

## Build

Requires CMake 4.4, Clang 22 or newer, a C++26 standard library supporting modules
and exclusive file creation, and Boost 1.91 (JSON and Program_options).

From the repository root:

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

`JSTS_BUILD_UBQT_REDACT` defaults to `ON`. Set it to `OFF` to omit this tool and
its dependency discovery. `JSTS_UBQT_REDACT_BOOST_USE_STATIC_LIBS` is an advanced
option initialized from `JSTS_BOOST_USE_STATIC_LIBS`. Libraries are discovered
inside this tool's subdirectory. The minimum Boost version is inherited through
`JSTS_BOOST_MIN`.

## Use

```sh
ubqt-redact redact --input boot.cfg --output boot.safe.cfg --map secrets.json
ubqt-redact restore --input router.safe.rsc --output router.rsc \
    --map secrets.json --escape routeros-value
ubqt-redact --help
```

Inputs must be regular files. All destinations must be new files. Input, output,
and map must be distinct;
existing aliases and symbolic links are checked. Map files and restored outputs
receive owner-only read/write permissions before secret content is written.
Permission failure aborts the operation. The checks are best effort, not an atomic
security boundary against concurrent changes to parent directories. Use a private,
trusted directory. Redaction creates the map first and removes it if writing the
sanitized output fails; the pair is not an atomic filesystem transaction.

## Detection and preservation

The lightweight scanner preserves text outside replacement spans, including
whitespace, quotes, comments, ordering, and braces. It supports double-quoted
values (escapes for quote, backslash, newline, carriage return, and tab), unquoted
atoms, newline/semicolon separators, and compact pairs of leaves on a line.
`#`, `//`, and `/* ... */` comments are recognized between tokens. These markers
inside an unquoted atom belong to that atom. Unsupported quoted escapes, missing
secret values, malformed comments/quotes/braces, and ambiguous token boundaries
are rejected. Columns count bytes, starting at one.

Rules cover:

- PPPoE users and passwords, including VLAN interfaces.
- Local plaintext/encrypted passwords and IPsec/L2TP/PPTP secrets.
- Dynamic DNS logins and passwords.
- SNMP community identifiers and v3 auth/privacy material. Algorithm `type` and
  `protocol` leaves remain visible.
- WireGuard `private-key` and `preshared-key` leaves.
- Generic `password`, `passwd`, `plaintext-password`, `encrypted-password`,
  `secret`, `shared-secret`, `pre-shared-secret`, `passphrase`, and `token` leaves.
  A warning reports the number of generic matches; records mark them for review.
- Raw PEM PRIVATE, RSA, EC, OPENSSH, ENCRYPTED, and DSA PRIVATE KEY blocks,
  including blocks in comments. A quoted scalar containing a private PEM block
  is redacted as one value. Partial overlaps are rejected.

Public keys, certificates, broad `key` leaves, and usernames outside explicit
credential rules remain unchanged. Future policies and helper commands mentioned
in HANDOFF.md are not implemented.

Each occurrence receives its own sentinel, even for repeated equal values:
`JSTS_SECRET_v1_<RUN_ID>_<KIND>_<SEQUENCE>`. Run IDs use 16 random ASCII characters;
sequence IDs follow source order. Sentinels stay stable within a map but differ
between redaction runs. Source containing `JSTS_SECRET_` is refused, including the
handoff's legacy leading-underscore spelling. Unknown, changed, unsupported-version,
or identifier-embedded sentinels fail restoration. Repeated known sentinels are
restored everywhere; unused map entries are allowed. Inserted secrets are never
scanned again.

Maps use format `jsts-secret-map`, version 1, with the exact prefix
`JSTS_SECRET_v1_`, source metadata, and ordered secret records. Each record stores
its kind, semantic value, source spelling/encoding, context, byte position, and
generic-rule flag. Duplicate JSON keys, duplicate or inconsistent sentinels,
invalid types/IDs, nested sentinels in secret values, and unsupported versions
are rejected. Original source spellings are metadata, not executable restore
instructions.

## Restore escaping

Restoration replaces sentinel text with value content and never adds quotes.
Choose escaping for the target context:

| Mode | Behavior |
| --- | --- |
| `raw` (default) | Insert the original semantic value unchanged. Use only in a context known to be safe. |
| `vyatta-value` | Escape quote, backslash, newline, carriage return, and tab for existing double quotes. |
| `routeros-value` | Also escape dollar signs; reject newline/carriage return values. Use existing double quotes. |
| `json-string-value` | JSON string escaping without enclosing quotes. |

RouterOS escaping follows the documented
[constant escape sequences](https://manual.mikrotik.com/docs/developer-guides/scripting/).
The tool does not parse or validate the target language. If conversion puts a
sentinel outside quotes, wrap it in double quotes before using a value escaping
mode. Raw restoration can reproduce ordinary source values, but semantic decoding
means escaped quoted source spellings need `vyatta-value`; exact literal-based
round trips are not provided.

## Limits and exit codes

Inputs and maps are limited to 16 MiB and valid UTF-8 without NUL or unsupported
control characters. Source scanning allows at most 1,000,000 tokens, 128 brace
levels, and 100,000 secret records. Collected metadata is also bounded to 16 MiB;
JSON expansion can cause map output to reach its limit earlier. Config outputs
are limited to 64 MiB, including expansion during restore. Map JSON nesting is
limited to 128 levels. Unsupported private PEM labels are rejected rather than
silently retained.

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Invalid command line or escaping mode |
| 3 | Input access, file size, or unsafe destination |
| 4 | Malformed source, redaction, or map generation failure |
| 5 | Malformed or unsupported secret map |
| 6 | Restore failure |
| 7 | Output write, permissions, or unexpected operation failure |

Diagnostics contain no original secret values. Tests use synthetic configurations
and cover redaction rules, quoting, PEM overlap, bounds, malformed maps, escaping,
unknown sentinels, CLI round trips, and filesystem aliases.
