# CrowdSec Syslog Notification Plugin

A standalone CrowdSec notification plugin written in Go. It receives the already-rendered notification text from CrowdSec and forwards it directly to a Syslog receiver.

## Features

- RFC 5424 message format (version 1, NILVALUE structured data)
- UDP transport
- TCP transport using RFC 6587 octet-counting framing
- Configurable facility, severity, hostname, app-name and MSGID
- Configurable connection/write timeout
- No third-party Syslog library
- Transport isolated behind `internal/syslog.Send`, allowing TLS support to be added later without changing the CrowdSec gRPC integration

**TLS is not implemented in this version.**

## Requirements

- Go 1.26.1 or newer (the CrowdSec v1.8.1 module currently declares Go 1.26.1)
- Network access for the initial Go dependency download
- A CrowdSec installation using a compatible notification plugin API

## Building

All commands below are executed from the project root directory using a Bash-compatible shell.

### Linux (amd64)

Build a statically linked Linux binary without dynamic library dependencies:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build -trimpath -ldflags="-s -w" \
-o notification-syslog ./cmd/notification-syslog
```

The resulting binary is named `notification-syslog`.

To verify the binary on Linux:

```bash
file notification-syslog
ldd notification-syslog
```

The binary should be reported as statically linked, and `ldd` should report that it is not a dynamic executable.

### Windows (amd64)

Cross-compile a native 64-bit Windows executable:

```bash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
go build -trimpath -ldflags="-s -w" \
-o notification-syslog.exe ./cmd/notification-syslog
```

The resulting executable is named `notification-syslog.exe`.

Both builds use the same Go source code and do not require platform-specific source changes.

### Other architectures

The plugin can also be cross-compiled for other architectures supported by Go. For example:

Linux ARM64:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
go build -trimpath -ldflags="-s -w" \
-o notification-syslog ./cmd/notification-syslog
```

## Installation

Check the actual plugin directory in `/etc/crowdsec/config.yaml` (`config_paths.plugin_dir`).

Common package installations use `/usr/lib/crowdsec/plugins/`; container and source installations may use a different directory.

Example for a Linux installation:

```bash
sudo install -o root -g root -m 0755 \
  notification-syslog /usr/lib/crowdsec/plugins/notification-syslog

sudo install -o root -g root -m 0644 \
  config/syslog.yaml /etc/crowdsec/notifications/syslog.yaml
```

Adjust the paths if your CrowdSec installation uses different directories.

CrowdSec plugin binaries must be installed with appropriate ownership and permissions. In particular, the binary must not be world-writable.

After installing or replacing the plugin binary, restart CrowdSec.

## Enable in a CrowdSec profile

Add the notification name to the relevant profile in `/etc/crowdsec/profiles.yaml`:

```yaml
notifications:
  - syslog_default
```

Do not replace an existing `notifications` list; add the entry to it.

The notification name must match the `name` configured in the notification YAML file.

After changing the profile, restart CrowdSec if required by your installation:

```bash
sudo systemctl restart crowdsec
```

## Configuration

See [`config/syslog.yaml`](config/syslog.yaml) for an example configuration.

| Key | Meaning | Example |
|---|---|---|
| `type` | Plugin type; must match the registered plugin type | `syslog` |
| `name` | Name referenced in the CrowdSec profile | `syslog_default` |
| `syslog_server` | Receiver address in `host:port` form | `192.0.2.50:514` |
| `syslog_protocol` | Transport protocol | `udp` or `tcp` |
| `syslog_facility` | RFC 5424 facility number, 0–23 | `16` (`local0`) |
| `syslog_severity` | RFC 5424 severity number, 0–7 | `4` (`warning`) |
| `syslog_hostname` | RFC 5424 HOSTNAME | `crowdsec01` |
| `syslog_appname` | RFC 5424 APP-NAME | `crowdsec` |
| `syslog_msgid` | RFC 5424 MSGID | `ALERT` |
| `timeout` | Maximum network operation duration | `5s` |

The PRI value is calculated as:

`PRI = facility * 8 + severity`

For `local0` and `warning`, the resulting PRI is `132`.

The IP address `192.0.2.50` is an example address from a range reserved for documentation. Replace it with the address or hostname of your actual Syslog receiver.

CrowdSec renders the `format` template itself. The plugin receives `notification.Text` and places that text in the RFC 5424 MSG field.

The plugin does not parse alert JSON or infer ban/unban transitions.

## Transport notes

- UDP sends one datagram.
- TCP uses RFC 6587 octet-counting: `<byte-count> <RFC5424-message>`.
- TLS is not supported in this version.
- The receiver must accept RFC 5424 and, for TCP, RFC 6587 octet-counting.
- Network errors are returned to CrowdSec so its notification retry mechanism can handle them.
- `max_retry` is configured in the CrowdSec notification YAML, not in this plugin's private configuration.

## Testing

Unit tests cover RFC 5424 formatting and header validation:

```bash
go test ./...
```

For an end-to-end test, configure a reachable Syslog receiver and trigger a test notification using the procedures supported by your installed CrowdSec version.

Verify that the message is received and correctly parsed by the Syslog receiver.

## Scope and known limitations

- CrowdSec dispatches notifications for alerts matching a profile. This plugin forwards those notifications; it does not independently monitor LAPI decisions.
- An alert notification is not an explicit decision-expired or unban event. Detecting unbans requires a separate decision lifecycle monitor or another event source.
- Message text is sent as a single RFC 5424 MSG field. CR/LF and NUL characters are normalized to spaces to avoid creating forged extra log lines.
- No TLS, reconnect queue, local spool or persistent delivery guarantee is implemented.
- UDP is inherently best-effort. Successful TCP transmission means the local socket accepted the bytes, not that the remote application durably stored them.

## References

- [CrowdSec: Writing a Plugin in Go](https://docs.crowdsec.net/docs/local_api/notification_plugins/writing_your_own_plugin/)
- [CrowdSec: Notification plugin introduction](https://docs.crowdsec.net/docs/local_api/notification_plugins/intro/)
- [RFC 5424: The Syslog Protocol](https://www.rfc-editor.org/rfc/rfc5424)
- [RFC 6587: Transmission of Syslog Messages over TCP](https://www.rfc-editor.org/rfc/rfc6587)

## License

This project is licensed under the MIT License.
See the [LICENSE](LICENSE) file for details.
