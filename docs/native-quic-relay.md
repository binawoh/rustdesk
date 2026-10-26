# Native QUIC relay in this fork

This fork can connect to a RustDesk relay through Hysteria 2 using QUIC inside the
RustDesk process. It does not launch `hysteria.exe`, run a PowerShell script, or
listen on a local TCP forwarding port. The VPS must already provide a Hysteria 2
endpoint that can reach its normal `hbbr` TCP listener.

The change applies to outgoing relay connections and incoming controlled sessions.
Device registration, peer discovery, direct connections, desktop authentication,
and RustDesk's end-to-end encryption keep their existing implementation.

## Configure

Place `quic-relay.private.json` beside `RustDesk.exe`:

```json
{
  "server": "quic.example.com:50000-50004",
  "relay": "relay.example.com:21117",
  "auth": "YOUR_HYSTERIA_AUTHENTICATION",
  "server_name": "quic.example.com",
  "certificate_sha256": "YOUR_SERVER_CERTIFICATE_SHA256",
  "hop_interval_seconds": 30
}
```

Use the normal public relay address in RustDesk's ID/Relay Server settings. It must
match `relay` above. Keep the global SOCKS/HTTP proxy empty. Only the configured
relay is routed through QUIC; other relays keep their original transport.

The SHA-256 fingerprint pins the complete DER server certificate and is mandatory.
TLS handshake signatures are also verified. Obtain the fingerprint through a
trusted channel and update it when the server certificate changes. Authentication
failure, a wrong fingerprint, or a failed QUIC connection produces an error; it
does not silently reconnect over TCP.

All ports in a hopping range must reach the same Hysteria 2 service. The client
uses BBR with a ten-packet initial congestion window and no fixed-rate Brutal mode.
The default hop interval is 30 seconds. A single server port disables hopping.

The file contains a secret. Restrict its filesystem permissions to the account
running RustDesk, plus its Windows service account when installed. Never commit
or distribute a populated private configuration. The filename is git-ignored.
Removing this file restores the original connection behavior for new sessions.

## Build and verify

The baseline is RustDesk 1.5.0 / Flutter 1.5.0+68. No Flutter FFI signatures change.
The `Native QUIC Windows` workflow builds the transport tests, a diagnostic probe,
the matching generated bridge, and the Windows backend DLL. Packaging must pair
that DLL with the same baseline's Windows launcher and Flutter assets.

```text
cargo test -p base --lib quic_relay --locked
cargo build -p base --example quic_relay_probe --locked
cargo run -p base --example quic_relay_probe -- PRIVATE_CONFIG SERVER_PUBLIC_KEY SSH_ALIAS 70
```

The probe starts a bounded Python test peer over SSH on the VPS, pairs an isolated
session through the real `hbbr`, verifies echoes across two port hops, and checks
2 MiB in each direction with SHA-256. It does not log into or control a desktop.
The probe and its Python fixture are development tools, not desktop dependencies.
Actual desktop rendering and input responsiveness require a separate two-client
test; transport success alone does not establish a performance improvement.

## Scope of existing code changes

- `src/client.rs`: choose the configured QUIC transport when initiating a relay.
- `src/server.rs`: choose it when accepting an incoming relayed session.
- `libs/base`: hold the client-only QUIC implementation and dependencies.

Both connection sites retain their original TCP path when QUIC is not configured.
The shared `hbb_common` submodule is unchanged; its existing framed-stream wrapper
continues to handle RustDesk messages and encryption over the new byte stream.

Protocol reference: <https://v2.hysteria.network/docs/developers/Protocol/>.
RustDesk's AGPL-3.0 license remains in effect. This fork does not push changes or
open pull requests against the upstream RustDesk repository.
