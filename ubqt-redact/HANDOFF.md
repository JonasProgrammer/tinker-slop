# ubqt handoff

## Purpose

`ubqt` is intended as a small C++26 tool for safely preparing Ubiquiti EdgeRouter
configuration files for AI-assisted workflows.

The primary source input is a saved Ubiquiti router configuration, usually
`/config/boot.cfg`, in a Vyatta/VyOS-like hierarchical brace format.

The tool should remove sensitive information from the configuration while retaining
the original structure as much as possible. It should emit:

1. A secret-free configuration containing stable sentinel values.
2. A separate mapping file containing the original secret values.

The sanitized configuration can then be shared with an AI or used in other
conversion workflows, for example conversion to MikroTik RouterOS configuration.
After conversion, the tool should be able to restore the original secret values by
replacing sentinel values in the generated text.

The restore step should not be tied to MikroTik. MikroTik RouterOS is the first
important target, but the design should work for arbitrary text-based configuration
formats.

Encryption of the mapping file is intentionally out of scope for now. The mapping
file is secret-bearing. Users are responsible for keeping it out of AI workflows,
version control, tickets, logs, and other untrusted locations.

## Project context

This repository contains independent small C++ tools. Keep this tool isolated in
its own `ubqt` subdirectory with its own `CMakeLists.txt` and `README.md`.

Follow the repository conventions:

- C++26.
- CMake target-scoped configuration.
- Boost 1.91 is available.
- Prefer C++ modules for project interfaces.
- Keep the root README tool index current when the tool becomes user-facing.
- Add a root build option, likely `JSTS_BUILD_UBQT`, defaulting to `ON`.
- Use project-owned CMake option prefixes beginning with `JSTS`.
- Do not couple this tool to existing tools.

Likely Boost dependencies:

- Boost.Program_options for the CLI.
- Boost.JSON for the mapping file.

A full parser is not required for the first version.

## Terminology

- Source config: the original Ubiquiti/Vyatta-style configuration containing
  secrets.
- Sanitized config: a structurally similar configuration where secrets are
  replaced with sentinel values.
- Secret map: JSON file containing sentinel-to-secret mappings.
- Sentinel: reversible placeholder inserted into sanitized/config-converted text.
- Restore/backfill: replacement of sentinels with original secret values.

## Design position

Prefer a value-based design.

This means sentinels represent secret values, not complete syntax fragments. The
redactor should preserve surrounding syntax where practical.

Example source:
```

text password "hunter2"```

Sanitized output:
```

text password "JSTS_SECRET_v1_K7P4M2Q9_PPPOE_PASSWORD_000001"``` 

The quotes remain part of the config syntax. The sentinel replaces only the value
content.

For an unquoted source value:
```

text password hunter2```

Sanitized output:
```

text password JSTS_SECRET_v1_K7P4M2Q9_PPPOE_PASSWORD_000001``` 

Restore should support replacing sentinels with escaped value content appropriate
for the chosen target format.

A literal-based restore mode may be useful later, but value-based replacement is
the preferred default.

## Non-goals for v1

Do not start by implementing a full Vyatta/VyOS parser.

Do not start by implementing a full RouterOS parser.

Do not implement mapping file encryption for v1.

Do not implement semantic Ubiquiti-to-MikroTik conversion in this tool. The tool is
for redaction and restoration around such workflows.

Do not support binary configuration formats in v1.

## Recommended high-level commands

Suggested CLI shape:
```

text ubqt redact
--input boot.cfg
--output boot.safe.cfg
--map secrets.json
text ubqt restore
--input mikrotik.safe.rsc
--output mikrotik.rsc
--map secrets.json
--escape routeros-value```

Useful future options:
```

text --redact-usernames --redact-public-keys never|fingerprint|always --redact-certificates never|fingerprint|always --generic-secret-rules on|off --fail-on-existing-sentinel --dry-run --report report.json --strict``` 

Possible helper commands:
```

text ubqt list --map secrets.json ubqt check-map --map secrets.json```

## Sentinel design

Sentinels should be recognizable, stable, and likely to survive AI and text-based
config conversions.

Use only conservative ASCII characters. Avoid whitespace, quotes, backslashes,
dollar signs, semicolons, braces, brackets, angle brackets, and slashes.

Recommended shape:
```

text JSTS_SECRET_v1 _``` 

Examples:
```

text JSTS_SECRET_v1_K7P4M2Q9_PASSWORD_000001 JSTS_SECRET_v1_K7P4M2Q9_PPPOE_USER_000002 JSTS_SECRET_v1_K7P4M2Q9_PPPOE_PASSWORD_000003 JSTS_SECRET_v1_K7P4M2Q9_PRIVATE_KEY_000004 JSTS_SECRET_v1_K7P4M2Q9_PSK_000005```

Properties:

- Pure ASCII.
- Identifier-like.
- No shell-special `$`.
- No whitespace.
- No RouterOS command separator `;`.
- No Vyatta structural braces.
- Versioned.
- Includes a per-run identifier to reduce accidental collisions.
- Includes a coarse secret kind.
- Includes a deterministic per-run sequence number.

Before redaction, scan the input for the sentinel prefix:
```

text _JSTS_SECRET_v1``` 

Fail by default if it already exists. This avoids ambiguous or nested redaction.
A future option may allow existing sentinels, but default behavior should be
conservative.

## Mapping file

Use JSON.

The mapping file is sensitive because it contains the original secrets in plain
text. This is acceptable for v1 because the user already has the original
secret-bearing input files and is responsible for keeping both out of untrusted
workflows.

Suggested structure:
```

json { "format": "jsts-secret-map", "version": 1, "run_id": "K7P4M2Q9", "source": { "kind": "ubiquiti-edgerouter-boot-cfg", "path": "boot.cfg" }, "sentinel_prefix": "_JSTS_SECRET_v1", "secrets": [ { "id": 1, "sentinel": "JSTS_SECRET_v1_K7P4M2Q9_PPPOE_USER_000001", "kind": "pppoe-user", "original": "customer@example", "context": { "path": "interfaces ethernet eth0 pppoe 0 user-id", "line": 123, "column": 21 } }, { "id": 2, "sentinel": "JSTS_SECRET_v1_K7P4M2Q9_PPPOE_PASSWORD_000002", "kind": "pppoe-password", "original": "super-secret-password", "context": { "path": "interfaces ethernet eth0 pppoe 0 password", "line": 124, "column": 22 } } ] }```

For quoted source values, consider storing both semantic and source-spelled forms:
```

json { "id": 3, "sentinel": "JSTS_SECRET_v1_K7P4M2Q9_PASSWORD_000003", "kind": "password", "original": "pa"ss", "source_literal": ""pa\"ss"", "source_encoding": "vyatta-double-quoted" }``` 

The semantic `original` value is what should be used for target-format escaping.

The `source_literal` can be useful for exact same-format round-tripping, but the
main design is value-based.

## Source scanner strategy

Implement a lightweight scanner, not a full parser.

For Vyatta-style configs, the scanner should understand enough syntax to:

- Preserve the original input text exactly except for redacted value spans.
- Track brace nesting.
- Track path atoms.
- Identify quoted string values.
- Identify unquoted atom values.
- Ignore comments where appropriate.
- Report line and column information for mappings and warnings.

Suggested token kinds:
```

text atom quoted_string left_brace right_brace semicolon newline comment```

Each token should carry byte offsets and line/column information.

For quoted strings, track both:

- Full token span including quotes.
- Inner value span excluding quotes.

The redactor should replace the value span when possible, preserving the original
quote delimiters.

The scanner should be robust against malformed input. External input is
malicious. Validate bounds and reject ambiguous or structurally dangerous cases
with useful errors. Do not rely on assertions.

## Redaction model

Collect redactions first, then apply them from the end of the input toward the
beginning.

Suggested types:
```

text SecretKind SecretRecord Redaction``` 

Conceptually:
```

text SecretRecord: id sentinel kind original optional source literal/spelling metadata path line column
Redaction: begin byte offset end byte offset replacement sentinel associated SecretRecord```

After collecting redactions:

1. Sort by byte offset.
2. Reject overlaps.
3. Apply replacements from highest offset to lowest offset.
4. Emit sanitized config and mapping JSON.

Default behavior should prefer one mapping entry per occurrence, not
deduplication. This avoids leaking that two secrets are equal and preserves
context for review.

A future `--deduplicate-secrets` option could intentionally reuse sentinels for
identical secret values.

## Secret detection rules

Use two complementary mechanisms:

1. Path-based rules for Vyatta-style brace configs.
2. Raw text block detection for private key material.

A generic fallback for obvious secret leaf names should exist and probably be
enabled by default, but produce warnings when used.

### Initial path-based rules

Redact PPPoE credentials:
```

text interfaces * pppoe * user-id interfaces * pppoe * password interfaces * vif * pppoe * user-id interfaces * vif * pppoe * password``` 

Redact local user passwords:
```

text system login user * authentication plaintext-password system login user * authentication encrypted-password```

Redact IPsec/L2TP/PPTP/shared secrets:
```

text vpn ipsec site-to-site peer * authentication pre-shared-secret vpn l2tp remote-access ipsec-settings authentication pre-shared-secret vpn pptp remote-access authentication local-users username * password``` 

Redact dynamic DNS credentials:
```

text service dns dynamic interface * service * login service dns dynamic interface * service * password```

Redact SNMP community strings and v3 auth/privacy material:
```

text service snmp community * service snmp v3 user * auth * service snmp v3 user * privacy *``` 

Redact WireGuard private material if present:
```

text
private-key
preshared-key```

Be careful with broad `key` rules. Not every path segment named `key` is secret.

### Generic secret leaf names

For any leaf whose final atom clearly indicates a secret, redact it:
```

text password passwd plaintext-password encrypted-password secret shared-secret pre-shared-secret private-key preshared-key passphrase token``` 

Generic matches should be reported as such so users can audit whether the tool is
over-redacting.

### Public keys and certificates

Public keys are not usually secret but can be identifying.

Certificates are not usually secret but can expose names and topology.

Default policy should probably leave them alone or fingerprint them in reports
only. Provide future options:
```

text --redact-public-keys never|fingerprint|always --redact-certificates never|fingerprint|always```

### Private key blocks

Independently scan raw text for private key PEM blocks:
```

text -----BEGIN PRIVATE KEY----- -----BEGIN RSA PRIVATE KEY----- -----BEGIN EC PRIVATE KEY----- -----BEGIN OPENSSH PRIVATE KEY-----``` 

Redact the whole private key block as one secret.

Multiline private keys are harder to restore into RouterOS command text. It is
fine for v1 to support redaction and mapping while restricting RouterOS restore of
multiline values.

## Restore design

Restore should be intentionally simple:

1. Load mapping JSON.
2. Scan arbitrary text for known sentinels.
3. Replace each sentinel with the mapped original value using the selected escaping
   mode.
4. Fail if unknown sentinels with the known prefix are present, unless an option
   explicitly allows them.

The restore operation should not need to parse MikroTik, Vyatta, or any other
target language.

Because the preferred model is value-based, restore should normally replace a
sentinel with escaped value content only.

Example sanitized RouterOS text:
```

text /interface pppoe-client add user="JSTS_SECRET_v1_K7P4M2Q9_PPPOE_USER_000001" password="JSTS_SECRET_v1_K7P4M2Q9_PPPOE_PASSWORD_000002"```

Restore with `routeros-value`:
```

text /interface pppoe-client add user="customer@example" password="super-secret-password"``` 

If a future literal mode is added, it would replace bare sentinels with complete
quoted literals:
```

text password=JSTS_SECRET_v1_K7P4M2Q9_PPPOE_PASSWORD_000002```

could become:
```

text password="super-secret-password"``` 

But value mode should be the default design.

## Escaping modes

Initial escaping modes should focus on value content:
```

text raw vyatta-value routeros-value json-string-value```

Potential future literal modes:
```

text vyatta-literal routeros-literal json-string-literal``` 

### raw

Insert the original secret without escaping. This is useful only when the caller
knows the target context is safe.

### vyatta-value

Escape a value for placement inside an existing Vyatta-style double-quoted string.
At minimum handle:
```

text "
newline carriage return tab```

### routeros-value

Escape a value for placement inside an existing MikroTik RouterOS double-quoted
string.

Be conservative. Escape at least:
```

text "
$ newline carriage return tab``` 

RouterOS multiline scalar handling should be treated carefully. For v1, it is
acceptable to reject multiline secrets in `routeros-value` mode unless a specific
and tested multiline encoding is implemented.

### json-string-value

Escape a value for placement inside an existing JSON string. This may be useful
for generated structured configs or tests.

## Important behavior choices

### Bias toward false positives over false negatives

A false positive removes too much useful context. A false negative leaks a secret
into the AI workflow.

Default rules should err on the side of redaction for obvious secret-bearing paths
and names.

A possible future `--paranoid` mode can redact more aggressively:

- Usernames under auth/PPP/VPN/DDNS.
- Public keys.
- Certificates.
- Any leaf named `key`.
- Any leaf named `login`.
- Any suspicious token under authentication-related paths.

### Preserve structure

The sanitized config should be syntactically valid or at least structurally close
to the source whenever practical.

Preserve whitespace, comments, ordering, braces, line breaks, and unrelated
values.

Only replace secret value spans.

### Mapping file secrecy

The mapping file is a secret-bearing artifact. README and CLI help should state
this clearly.

Do not log secret values.

Diagnostics may mention sentinel, kind, path, line, and column, but not original
secret content.

### Input and output safety

All input is malicious.

Bound file size. A practical starting limit such as 16 MiB is reasonable for
router configs.

Check output path identity against input path as a best-effort safety measure,
but document that this is not an atomic security boundary.

Reject malformed mapping files with useful errors.

Reject duplicate sentinel records in the map.

Reject unknown sentinel prefixes during restore by default.

## Suggested tests

Use synthetic fixtures. Do not use real router configs.

### Redaction basics

Input:
```

text interfaces { ethernet eth0 { pppoe 0 { user-id "alice@example" password "hunter2" } } }```

Expected:

- User and password are replaced by sentinels.
- Structure and whitespace are preserved.
- Map contains two records with correct kinds and paths.

### Quoting

Test all of these:
```

text password simple password "simple" password "with spaces" password "with " quote" password "with \ backslash"``` 

Verify semantic value extraction and sanitized output.

### Repeated equal secrets

By default, repeated equal values should get separate sentinel records.

### Existing sentinel collision

Input containing:
```

text _JSTS_SECRET_v1```

should fail by default.

### Generic secret fallback

A leaf named `secret` or `token` outside known paths should be redacted and
reported as a generic match.

### Private key block

A PEM private key block should be replaced as one secret.

### Restore value mode

Given a RouterOS-like input with sentinels inside quotes, restore should replace
with RouterOS-escaped value content.

### Unknown sentinel in restore

A text containing a known-prefix sentinel that is not present in the map should
fail by default.

### Overlap rejection

Construct a case where path-based and PEM/block-based redactions overlap. The
redactor should reject overlapping spans or deterministically coalesce them. Do not
silently produce corrupt output.

## Likely module layout

Suggested files:
```

text ubqt/ CMakeLists.txt README.md HANDOFF.md domain.cpp scanner.cpp rules.cpp redact.cpp restore.cpp escaping.cpp map_json.cpp ubqt.cpp tests.cpp``` 

Suggested modules:
```

text ubqt.domain ubqt.scanner ubqt.rules ubqt.redact ubqt.restore ubqt.escaping ubqt.map_json```

Keep implementation details private where possible.

## Suggested exit statuses

A possible scheme:
```

text 0 success 2 invalid command line 3 input access error or unsafe output path 4 malformed source config or redaction failure 5 malformed mapping file 6 restore failure 7 output write error``` 

The exact numbers are less important than documenting them.

## Implementation notes

Do not use Boost.Spirit for v1 unless a full grammar becomes necessary. A custom
scanner is likely easier to reason about because the tool needs exact byte spans
and should preserve original text.

Use Boost.JSON for deterministic map writing/reading.

Use Boost.Program_options for the CLI.

Keep comments terse and ASCII-only.

Do not print original secrets in errors, warnings, or tests.

## First useful milestone

Implement a minimal but complete vertical slice:

1. `ubqt redact`.
2. Lightweight Vyatta scanner.
3. PPPoE `user-id` and `password` redaction.
4. JSON map output.
5. `ubqt restore`.
6. Raw and RouterOS value escaping.
7. Tests for quoted/unquoted PPPoE credentials and restore.

After that, expand rule coverage.
```
