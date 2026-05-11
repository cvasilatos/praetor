# Praetor

[![Tests](https://github.com/cvasilatos/praetor/actions/workflows/tests.yml/badge.svg)](https://github.com/cvasilatos/praetor/actions/workflows/tests.yml)
[![Build](https://github.com/cvasilatos/praetor/actions/workflows/build.yml/badge.svg)](https://github.com/cvasilatos/praetor/actions/workflows/build.yml)
[![Docs](https://github.com/cvasilatos/praetor/actions/workflows/docs.yml/badge.svg)](https://github.com/cvasilatos/praetor/actions/workflows/docs.yml)
![Python](https://img.shields.io/badge/python-3.14-blue.svg)
![Package Manager](https://img.shields.io/badge/package%20manager-uv-5c2d91.svg)

Praetor validates industrial protocol payloads in two complementary ways:

- Sends request payloads to a local [Cursus](https://github.com/cvasilatos/cursus)-managed protocol server and checks the returned response with a user-provided callback.
- Parses request or response payloads with PyShark/Wireshark and fails when Wireshark reports malformed packets or when the expected protocol layers are missing.

The package is intended for fuzzers, generators, and test suites that need a quick "does this payload still look like this protocol?" check before keeping or mutating a packet.

## Requirements

- Python `>=3.14`
- `tshark` installed and available on `PATH` for PyShark packet parsing
- Network access during installation if `uv` needs to fetch the Git-based `decima` and `cursus` dependencies
- Available local ports for the protocol emulators listed below

Verify the Wireshark CLI dependency before using the PyShark validator:

```sh
tshark -v
```

On macOS with Homebrew, `tshark` is installed with Wireshark:

```sh
brew install wireshark
```

On Debian or Ubuntu:

```sh
sudo apt-get install tshark
```

## Installation

From a checkout of this repository:

```sh
uv sync
uv pip install -e .
```

For development, include the test and tooling groups:

```sh
uv sync --all-groups
```

If this package is consumed from another project before it is published to a package index, install it from the Git repository or from a local path:

```sh
uv add "praetor @ git+https://github.com/<owner>/praetor.git"
uv add "praetor @ file:///absolute/path/to/praetor"
```

## Quick Start

Import `Praetor` from `praetor.praetord`:

```python
from praetor.praetord import Praetor
from praetor.protocol_info import ProtocolInfo


def is_valid_mbtcp_response(response_hex: str) -> bool:
    """Accept non-empty Modbus TCP responses that are not exception responses."""
    if len(response_hex) < 16:
        return False

    function_code = int(response_hex[14:16], 16)
    return function_code < 0x80


validator = Praetor([ProtocolInfo.MBTCP], is_valid_mbtcp_response)

try:
    request_hex = "000100000006010300000001"

    if validator.combined_validator.validate(request_hex, protocol="mbtcp"):
        print("valid packet")
finally:
    validator.device_validator.close()
    validator.pyshark_validator.close()
```

Packets are passed as hexadecimal strings. They should not include a `0x` prefix; spaces are accepted because Praetor uses Python's `bytes.fromhex()`.

Praetor can also validate against more than one protocol. Pass `ProtocolInfo` values in priority order and either provide one shared response callback or a mapping of protocol names to protocol-specific callbacks:

```python
validator = Praetor(
    [ProtocolInfo.MBTCP, ProtocolInfo.S7COMM],
    {
        "mbtcp": is_valid_mbtcp_response,
        "s7comm": lambda response_hex: bool(response_hex),
    },
)

if validator.combined_validator.validate(request_hex, protocol="mbtcp"):
    print("valid Modbus TCP packet")
```

Each validation call must specify the packet's protocol. Praetor validates only that protocol for the packet.

## Validators

### Combined Validator

`validator.combined_validator.validate(packet_hex, protocol="mbtcp")` runs both validators and returns `True` only when both accept the packet.

1. Parses `packet_hex` with PyShark.
2. Sends `packet_hex` to the local protocol server with the device validator.

Validation failures return `False`, giving apps that need both validators a single packet-validity check.

### Device Validator

`validator.device_validator.validate(packet_hex, protocol="mbtcp")` sends `packet_hex` to a local protocol server and returns the raw response bytes when the response passes your callback.

The callback passed to `Praetor(protocols, is_valid_response)` receives the response as a lowercase hex string:

```python
def is_valid_response(response_hex: str) -> bool:
    return bool(response_hex)
```

Use the callback to enforce protocol-specific expectations such as transaction IDs, function codes, minimum lengths, or acceptable status bytes.

The device validator:

- Starts a local Cursus server for each configured protocol.
- Connects to `localhost` on the protocol's custom port.
- Sends TCP payloads with `sendall()` and UDP payloads with `send()`.
- Reconnects the managed socket after `OSError`, then re-raises the original error so callers can decide whether to retry.
- Raises `ValueError` when no response is received or when the callback rejects the response.

When configured with multiple protocols, the device validator starts one local Cursus server per protocol. Each `validate(packet_hex, protocol="mbtcp")` call validates the packet against exactly one configured protocol.

### PyShark Validator

`validator.pyshark_validator.validate(packet_hex, is_request=True, protocol="mbtcp")` wraps the payload in Ethernet/IP/TCP or Ethernet/IP/UDP layers, parses it with PyShark, and returns the parsed packet object.

Use `is_request=True` for client-to-server payloads and `is_request=False` for server-to-client payloads:

```python
request_packet = validator.pyshark_validator.validate("000100000006010300000001", is_request=True, protocol="mbtcp")
response_packet = validator.pyshark_validator.validate("000100000005010302000a", is_request=False, protocol="mbtcp")
```

The PyShark validator:

- Uses the protocol's default port as the destination port for requests.
- Uses the protocol's default port as the source port for responses.
- Uses UDP for BACnet requests and TCP for the other supported protocols.
- Keeps TCP sequence and acknowledgment numbers moving between validations on the same validator instance.
- Raises `ValidatorWiresharkError` when Wireshark expert info marks the packet as malformed.
- Raises `ValidatorError` when the expected protocol layer set is not present.

When configured with multiple protocols, the PyShark validator keeps independent TCP sequence state for each protocol. Each `validate(packet_hex, is_request=True, protocol="s7comm")` call validates the packet against exactly one configured protocol.

For independent packet conversations, create a fresh `Praetor` instance so sequence and acknowledgment state starts over.

## Supported Protocols

`ProtocolInfo.from_name()` accepts either the protocol name or the enum member name, case-insensitively. For example, `mbtcp` and `MBTCP` both resolve to the Modbus TCP metadata. Validator constructors accept a non-empty list of `ProtocolInfo` enum values.

| Protocol argument | Enum name | Transport | Wireshark/default port | Local emulator port | Expected layers |
| --- | --- | --- | ---: | ---: | --- |
| `mbtcp` | `MBTCP` | TCP | 502 | 5020 | `mbtcp`, `modbus` |
| `s7comm` | `S7COMM` | TCP | 102 | 10200 | `s7comm` |
| `iec104` | `IEC104` | TCP | 2404 | 24040 | `iec60870_104` |
| `dnp3` | `DNP3` | TCP | 20000 | 20000 | `dnp3` |
| `enip` | `ENIP` | TCP | 44818 | 44818 | `enip` |
| `bacnet` | `BACNET` | UDP | 47808 | 47808 | `bvlc`, `bacnet`, `bacapp` |
| `hart` | `HART_IP` | TCP | 5094 | 5094 | `hart_ip` |
| `ads` | `ADS` | TCP | 48898 | 48898 | `ams` |

Unknown protocol names raise `ValueError`.

## Error Handling

Import validation errors directly from their modules:

```python
from praetor.exceptions.validator_error import ValidatorError
from praetor.exceptions.validator_wireshark_error import ValidatorWiresharkError
```

Both validation error classes expose:

- `pdu`: the parsed packet that failed validation.
- `is_request`: whether the failed packet was parsed as a request.

Example:

```python
from praetor.exceptions.validator_error import ValidatorError
from praetor.exceptions.validator_wireshark_error import ValidatorWiresharkError
from praetor.praetord import Praetor
from praetor.protocol_info import ProtocolInfo


validator = Praetor([ProtocolInfo.MBTCP], lambda response_hex: bool(response_hex))

try:
    validator.pyshark_validator.validate("deadbeef", is_request=True, protocol="mbtcp")
except ValidatorWiresharkError as exc:
    print(f"Wireshark rejected request={exc.is_request}: {exc}")
except ValidatorError as exc:
    print(f"Expected protocol layers were missing: {exc.pdu}")
finally:
    validator.device_validator.close()
    validator.pyshark_validator.close()
```

Other common exceptions:

- `ValueError`: invalid hex, unknown protocol, empty device response, or callback-rejected response.
- `OSError`: socket send/receive failure. Praetor reconnects before re-raising.
- `RuntimeError`: attempting to use a closed PyShark validator.
- `TimeoutError`: the local Cursus server did not become ready within the startup timeout.

## Resource Cleanup

`Praetor` owns a socket connection, a local protocol server, and a PyShark capture. Close both validators when done:

```python
validator.device_validator.close()
validator.pyshark_validator.close()
```

The classes also perform best-effort cleanup in destructors, but explicit cleanup is preferred in scripts, tests, and long-running processes.

## Logging

Praetor uses standard Python loggers named after each class module, such as `praetor.praetord.Praetor` and `praetor.validator.pyshark_validator._PysharkValidator`.

Enable debug logs while troubleshooting packet parsing or socket reconnects:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
```

## Development

Install all development dependencies:

```sh
uv sync --all-groups
```

Run the checks used by the repository hooks:

```sh
uv run ruff check
uv run ruff format --check
uv run ty check
uv run pytest
uv run mkdocs build --strict
```

If `pre-commit` is installed, run the full hook set:

```sh
pre-commit run --all-files
```

Build or serve the documentation locally:

```sh
uv run mkdocs build --strict
uv run mkdocs serve
```

The docs home page includes this README, so changes here are reflected in the generated documentation site.
