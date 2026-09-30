# roc-scram

Client-side SCRAM-SHA-256 authentication (RFC 5802, RFC 7677) in pure Roc, with channel binding for SCRAM-SHA-256-PLUS (`tls-server-end-point`, RFC 5929). It builds and checks the SASL messages and leaves carrying them to you, so the same code serves any protocol that authenticates with SCRAM: PostgreSQL, MongoDB, Kafka, SMTP and IMAP.

Uses the built-in crypto from Roc and [roc-hmac](https://github.com/niclas-ahden/roc-hmac) (HMAC-SHA-256 and PBKDF2) and [roc-base64](https://github.com/niclas-ahden/roc-base64).

See the documentation at [https://niclas-ahden.github.io/roc-scram/](https://niclas-ahden.github.io/roc-scram/).

## Usage

```roc
app [main!] {
    pf: platform "https://github.com/roc-lang/basic-cli/releases/download/0.23.0/GNN5tt2gKdX4dhawg4915C4YB193woHFdcCkz31fhGxv.tar.zst",
    scram: "https://github.com/niclas-ahden/roc-scram/releases/download/0.1.0/5LZNjdSHw4qQtdQcfLy6P5B7dCA9gqa1c16TUZDA6gSz.tar.zst",
}

import scram.Scram

binding = Scram.select({
    offered: ["SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"],
    transport: TlsWithEndPoint(end_point),
    require_channel_binding: Bool.True,
})?

first = Scram.start({ username: "", password, nonce, channel_binding: binding })?
send!(first.mechanism(), first.message())?

final = first.receive_server_first(receive!()?)?
send!(final.message())?

# Only now has the server proved it knows the password
final.verify_server_final(receive!()?)?
```

- `nonce` is at least 18 bytes from a secure random source. In [`roc-lang/basic-cli`](https://github.com/roc-lang/basic-cli), three calls to `Random.seed_u64!` give 24 bytes from the operating system.
- `ClientFirst` and `ClientFinal` are separate types, so the steps can only run in order.
- `examples/main.roc` plays a recorded exchange end to end.
- [roc-pg](https://github.com/niclas-ahden/roc-pg) logs in to PostgreSQL with this package, and its integration tests run it against a real server.

## What it checks

- **The server's proof.** `verify_server_final` compares the server's signature in constant time ([`roc-hmac`](https://github.com/niclas-ahden/roc-hmac)'s `Hmac` equality). A protocol must not treat the login as done before it succeeded, even if the server says so.
- **Downgrades.** `select` with `require_channel_binding` refuses anything but SCRAM-SHA-256-PLUS over TLS. Without the requirement, TLS to a server that does not offer PLUS sends the `y` flag, so a PLUS offer stripped in transit is detected by the server.
- **The server-first-message.** The server's nonce must extend the client's and be printable ASCII. The salt must be non-empty base64. An `m=` extension the client must understand fails the login. The iteration count is digits without a leading zero and must lie within `min_iterations` (default 4096) and `max_iterations` (default 1,000,000), and `start` refuses a minimum above the maximum.
- **The server's refusal.** An `e=` reason comes back as `ServerError(reason)`.

## Limitations

- SASLprep (RFC 4013) is not applied to the username or the password. ASCII is unaffected. A password that SASLprep changes (unnormalized Unicode, non-ASCII spaces, soft hyphens) fails against a server that normalized it when it stored the password, as PostgreSQL does. Such a username may not be found by a server that expects it prepared. PostgreSQL ignores the SCRAM username, so there only the password matters.
- Only `tls-server-end-point` channel binding, no `tls-exporter` or `tls-unique`.
- Channel binding needs a platform that speaks TLS and hands over the connection's `tls-server-end-point` value. [roc-lang/basic-cli](https://github.com/roc-lang/basic-cli) and [roc-lang/basic-webserver](https://github.com/roc-lang/basic-webserver) do not speak TLS at the time of writing, so there it is SCRAM-SHA-256 over `Plain`, and SCRAM-SHA-256-PLUS is checked against the test vectors only.
- No authorization identity (`a=`) and no client extensions.
- SCRAM-SHA-256 only, not SCRAM-SHA-1 or SCRAM-SHA-512.

## Development

```sh
nix develop -c roc test package/main.roc
nix develop -c roc examples/main.roc
```

The unit tests hold RFC 7677's test vector and three exchanges computed with Python's `hashlib` and `hmac`, an implementation independent of this one. They cover username escaping, the `y` flag and 32- and 48-byte channel bindings, every refusal above, the iteration bounds given to `start`, and every combination of offer, transport and requirement in `select`.

Logins against a real PostgreSQL server are tested in [roc-pg](https://github.com/niclas-ahden/roc-pg), which depends on this package: a plain login, a wrong password, a non-ASCII password, one that SASLprep changes, and servers that ask for too few or too many iterations.
