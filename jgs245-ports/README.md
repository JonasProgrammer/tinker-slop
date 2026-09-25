# jgs245-ports

`jgs245-ports` analyzes NETGEAR JGS524Ev2 configuration backups and exports the
802.1Q VLAN configuration in a port-centric form. It currently targets backups
from firmware 2.6.0.50 using config format v2.2.3. Other firmware or format
versions are accepted with a warning when the known structures still validate.

The input file is opened read-only. The tool performs a best-effort check that
the output path does not resolve to the input file.

## Security

Treat configuration backups as secrets. They can contain password-related
material and other sensitive settings. Do not upload or commit a real backup
without reviewing how it was collected and sanitized.

Normal output exposes only decoded device and VLAN data. `--dump-records` writes
record offsets, types, sizes, and knowledge labels to stderr; it deliberately
omits payload bytes. Even that structural metadata can reveal configuration
details, so diagnostic use prints a security notice.

The input/output identity check is not atomic with opening the output. A local
attacker who can replace directory entries concurrently could race the check
with a symlink or hard link. Do not write reports into an attacker-controlled
directory when preserving the input is security-critical.

The repository ignores `*.cfg` files.

## Requirements and build

- CMake 4.4 or newer
- Clang 22 or newer
- A C++26 standard library
- Boost 1.91 or newer with JSON and Program_options
- Ninja (for the commands below; another CMake generator may also be used)

From the repository root:

```sh
cmake -S . -B build -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=/etc/static/dev-profiles/cpp-clang.cmake
cmake --build build
ctest --test-dir build --output-on-failure
```

Install with an optional prefix:

```sh
cmake --install build --prefix "$HOME/.local"
```

The root option `JSTS_BUILD_JGS245_PORTS` controls whether the tool is built.
It defaults to `ON`. The advanced
`JSTS_JGS245_PORTS_BOOST_USE_STATIC_LIBS` option inherits the root
`JSTS_BOOST_USE_STATIC_LIBS` preference.

## Usage

The default output is a compact port-centric terminal table:

```sh
jgs245-ports switch.cfg
jgs245-ports switch.cfg --show-vlans
```

Choose another format with `--format` and write it with `--output`:

```sh
jgs245-ports switch.cfg --format json > switch.json
jgs245-ports switch.cfg --format csv -o switch.csv
jgs245-ports switch.cfg --format html -o report.html
```

HTML can also be written to stdout. The generated report is a standalone file
with embedded CSS and no scripts, network requests, or proprietary assets.

Useful diagnostic options:

```sh
jgs245-ports switch.cfg --dump-records
jgs245-ports switch.cfg --strict --format json
jgs245-ports --version
```

Warnings go to stderr so JSON and CSV on stdout stay valid. `--strict` rejects
any warning before writing normal output.

Exit statuses are:

| Status | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | Invalid command line |
| 3 | Input access error or attempted input overwrite |
| 4 | Malformed or unsupported configuration |
| 5 | Warning rejected by `--strict` |
| 6 | Output write error |

## Output formats

### Table

The default table has one row per physical port and columns for PVID, untagged
VLANs, and tagged VLANs. Runs of three or more consecutive values are displayed
as ranges. `--show-vlans` appends a VLAN-centric view.

### JSON

JSON keys and array ordering are deterministic. VLANs are ordered by VLAN ID and
ports by physical port number. A missing PVID is `null`.

```json
{
  "device": {
    "model": "JGS524Ev2",
    "firmware": "2.6.0.50",
    "config_format": "v2.2.3"
  },
  "ports": [
    {
      "port": 1,
      "pvid": 1,
      "member_vlans": [1, 3, 4, 5, 6],
      "tagged_vlans": [3, 4, 5, 6],
      "untagged_vlans": [1]
    }
  ],
  "vlans": [
    {
      "vlan_id": 4,
      "member_ports": [1, 14, 24],
      "tagged_ports": [1],
      "untagged_ports": [14, 24]
    }
  ],
  "warnings": []
}
```

The actual serializer emits compact JSON followed by a newline.

### CSV

CSV columns are:

```text
port,pvid,member_vlans,untagged_vlans,tagged_vlans
```

Multiple VLAN IDs in one cell use a semicolon, for example `1;3;4;5;6`. Cells
contain only decimal numbers and semicolons. A missing PVID produces an empty
cell.

### HTML

The standalone report includes device metadata, a responsive 24-port strip, a
port-centric detail table, a VLAN matrix, a Tagged/Untagged/Not Member legend,
and warnings.

## Validation behavior

The parser validates the fixed header fields, bounded nested records, VLAN IDs,
physical port IDs, PVID values, duplicate VLAN/PVID records, and the rule that a
tagged bitmap must be a subset of membership. Structural violations are fatal.

All 24 ports appear in the output. A missing PVID record is a warning. A PVID
that does not match an untagged membership is also a warning; the tool reports
the inconsistency and does not rewrite either value.

The parser independently caps input at 16 MiB, VLAN records at 4094, PVID
records at 24, and records following the PVID table at 4096. A partial trailing
header or a trailing record whose declared size exceeds the input produces a
warning, so `--strict` rejects it.

Every renderer validates the domain model before constructing output. Limits
cover metadata and warning text, port/VLAN cardinalities, per-record lists, and
diagnostic summaries. These checks prevent an oversized programmatically-built
model from causing unbounded output allocation.

## Format knowledge and limitations

The decoded fields and their evidence are documented in
[docs/format.md](docs/format.md). In summary:

- VERIFIED: fixed metadata strings at the observed offsets, VLAN payload fields,
  24-bit port bitmap order, and per-port PVID payload fields.
- INFERRED: the general type/24-bit-length framing and the interpretation of the
  outer VLAN and PVID records as containers.
- UNKNOWN: the trailing VLAN byte and record types including `0x38`, `0x4c`,
  `0x50`, `0x58`, `0x88`, and `0x94`.

The parser anchors on an adjacent, internally consistent VLAN/PVID container
pair instead of treating arbitrary `0x28` or `0x30` bytes as records. It does not
decode hostname, authentication material, or other switch features. It does not
claim that the inferred framing applies to every firmware or every record in the
file.

## Contributing format evidence

Differential samples are most useful: change one GUI setting, export before and
after backups, and report the exact firmware plus the changed setting. Keep raw
backups private unless they have been reviewed for secrets. A contribution can
instead include the smallest relevant byte ranges, their original offsets,
redacted metadata, GUI observations, and a clear distinction between repeated
observations and hypotheses. Tests should use synthetic fixtures whenever
possible.
