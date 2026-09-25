# JGS524Ev2 configuration format notes

These notes cover only the fields needed for VLAN and PVID reporting. Knowledge
is labeled as follows:

- VERIFIED: independently checked against the switch GUI for the supplied sample
  description.
- INFERRED: strongly supported by record sizes and repetition, but not proven as
  a general vendor format rule.
- UNKNOWN: observed bytes without established semantics.

No real configuration backup is stored in this repository.

## Header metadata

The sample description identifies these NUL-terminated printable ASCII strings:

| Offset | Size inspected | Meaning | Sample | Knowledge |
| ---: | ---: | --- | --- | --- |
| `0x00` | 20 bytes | Model | `JGS524Ev2` | VERIFIED |
| `0x14` | 20 bytes | Config format | `v2.2.3` | VERIFIED |
| `0x28` | 20 bytes | Firmware | `2.6.0.50` | VERIFIED |
| `0x3c` | Not decoded | Observed `v1` string | `v1` | UNKNOWN |

The parser validates the first three fields. It requires the JGS524Ev2 model.
An unfamiliar firmware or config format is a warning if the VLAN/PVID structure
still validates.

## Record framing

Observed records begin with a one-byte type followed by a three-byte big-endian
value. For the VLAN and PVID tables, that value exactly equals the complete
record size, including the four-byte header.

This framing interpretation is INFERRED. It is not asserted as a universal rule
for all bytes or firmware versions.

The evidence from the sample is:

| Record | Observed size | Size calculation |
| --- | ---: | --- |
| VLAN outer record | `0x6c` (108) | 4-byte header + 8 x 13-byte child records |
| VLAN child record | `0x0d` (13) | 4-byte header + 9-byte payload |
| PVID outer record | `0xac` (172) | 4-byte header + 24 x 7-byte child records |
| PVID child record | `0x07` (7) | 4-byte header + 3-byte payload |

The PVID outer record begins immediately after the VLAN outer record. The parser
uses the adjacent pair and validates every child boundary before decoding any
payload. It does not scan the entire input and accept each `0x28` or `0x30` byte
as a record marker.

## VLAN child payload

A validated 13-byte VLAN child has this observed layout:

| Child offset | Size | Meaning | Encoding | Knowledge |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | Record type `0x28` | Byte | INFERRED framing |
| 1 | 3 | Complete child size `0x00000d` | Big endian | INFERRED framing |
| 4 | 2 | VLAN ID | Big-endian unsigned 16-bit | VERIFIED |
| 6 | 3 | Membership bitmap | 24 ports | VERIFIED |
| 9 | 3 | Tagged-port bitmap | 24 ports | VERIFIED |
| 12 | 1 | Meaning unknown; observed as `0x03` | Byte | UNKNOWN |

Valid VLAN IDs are 1 through 4094. Tagged bits must be a subset of membership.
Untagged membership is calculated as `membership AND NOT tagged`, restricted to
the 24 bitmap bits. The final byte is retained in the internal model and is not
assigned a meaning.

### Bitmap order

The first bitmap byte describes ports 1 through 8, the second ports 9 through
16, and the third ports 17 through 24. Within each byte the most significant bit
is the lowest port number:

```text
byte 0: bit 7 -> port 1,  ... bit 0 -> port 8
byte 1: bit 7 -> port 9,  ... bit 0 -> port 16
byte 2: bit 7 -> port 17, ... bit 0 -> port 24
```

### Worked VLAN 4 example

```text
28 00 00 0d 00 04 80 04 01 80 00 00 03
|  |--------| |---| |------| |------|  |
|      |       |       |         |      +-- UNKNOWN (observed 0x03)
|      |       |       |         +--------- tagged bitmap: port 1
|      |       |       +------------------- members: ports 1, 14, 24
|      |       +--------------------------- VLAN ID 4
|      +----------------------------------- complete record size 13 (INFERRED)
+------------------------------------------ record type 0x28 (INFERRED framing)
```

Thus VLAN 4 has tagged port 1 and untagged ports 14 and 24. This agrees with the
GUI observation.

Other verified cross-checks are:

| VLAN | Members | Tagged | Untagged |
| ---: | --- | --- | --- |
| 5 | 1, 11 | 1, 11 | none |
| 6 | 1, 7 | 1, 7 | none |
| 2000 | 15-20 | none | 15-20 |

## PVID child payload

A validated 7-byte PVID child has this observed layout:

| Child offset | Size | Meaning | Encoding | Knowledge |
| ---: | ---: | --- | --- | --- |
| 0 | 1 | Record type `0x30` | Byte | INFERRED framing |
| 1 | 3 | Complete child size `0x000007` | Big endian | INFERRED framing |
| 4 | 1 | Physical port | 1 through 24 | VERIFIED |
| 5 | 2 | PVID | Big-endian unsigned 16-bit | VERIFIED |

Example:

```text
30 00 00 07 0f 07 d0
            |  |---|
            |    +--- PVID 2000
            +-------- physical port 15
```

The verified sample mapping is:

| Ports | PVID |
| --- | ---: |
| 1-10 | 1 |
| 11 | 3 |
| 12-13 | 1 |
| 14 | 4 |
| 15-20 | 2000 |
| 21-23 | 1 |
| 24 | 4 |

PVID and untagged membership are kept as separate facts. A mismatch produces a
warning rather than an inferred correction.

## Undecoded records

Observed table types `0x38`, `0x4c`, `0x50`, `0x58`, `0x88`, and `0x94` remain
UNKNOWN. The diagnostic record summary can show offset, type, and inferred size
for records following the verified anchor. It does not print their payload or
assign a setting name.

The parser accepts at most 4096 well-framed records after the PVID table. Bytes
that cannot form a complete inferred record header, or a record whose declared
size extends past the input, produce a warning rather than being silently
ignored. Strict mode rejects that warning. These checks validate framing only;
they do not assign semantics to an unknown record.

Future decoders should be added by record type, with fixtures that demonstrate
controlled GUI changes and clear VERIFIED, INFERRED, and UNKNOWN labels.
