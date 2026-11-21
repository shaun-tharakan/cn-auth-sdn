# Authentication protocol (TCP, newline-delimited JSON)

* Transport: TCP, default port **5000**. One JSON object per line (UTF-8, terminated by `\n`), max 4096 bytes.
* One request → exactly one response line. A connection may carry many requests; idle connections are closed after 30 s.
* Every response has `"ok": true|false`. Failures add `"error"` (machine code) and `"message"` (for people).
* The server decides identity from the TCP source address, never from a field in the message.

| `op` | Request fields | Success response | Error codes |
|---|---|---|---|
| `ping` | – | `{"ok":true,"op":"ping","server":"cn-auth","time":...}` | – |
| `login` | `username`, `password` | `session_id`, `username`, `role`, `host`, `client_ip`, `expires_at`, `ttl_seconds`, `allowed_services` | `invalid_credentials`, `locked_out` (+`retry_after`), `bad_request` |
| `access` | `session_id`, `service` | `granted:true`, `service`, `host`, `service_ip`, `service_port`, `expires_at`, `reason`, `flows` | `invalid_session`, `session_expired`, `access_denied` (+`code`: `role_not_permitted`, `unknown_service`, `session_ip_mismatch`, `unknown_host`), `controller_unavailable`, `controller_rejected` |
| `status` | `session_id` | `username`, `role`, `host`, `seconds_remaining`, `services`, `allowed_services` | `invalid_session`, `session_expired` |
| `logout` | `session_id` | `message`, `network_access_revoked` (false = revocation pending) | `invalid_session` |

Generic errors: `bad_json`, `bad_request`, `unknown_op`, `message_too_large`, `timeout`, `server_busy`, `internal_error`.

Example (the `\n` ends each line):

```
→ {"op":"login","username":"alice","password":"alice-demo-pw"}
← {"ok":true,"session_id":"EOt7Iv4n…","username":"alice","role":"student","host":"h1","client_ip":"10.10.0.1","expires_at":1761383948.2,"ttl_seconds":300,"allowed_services":["protected-echo"]}
→ {"op":"access","session_id":"EOt7Iv4n…","service":"protected-echo"}
← {"ok":true,"granted":true,"service":"protected-echo","host":"h1","service_ip":"10.10.0.100","service_port":9000,…}
```

Security notes: passwords are scrypt-hashed at rest (`scrypt$n$r$p$salt$hash`), never logged; session ids are 256-bit `secrets.token_urlsafe`
values; unknown users cost the same CPU as wrong passwords and get the same message; 5 failures per (IP, username) lock that pair for 30 s.

## Controller policy API (auth server → controller, HTTP on 127.0.0.1:8080)

| Method, path | Auth | Body | Effect |
|---|---|---|---|
| `POST /policy/grant` | `X-Policy-Token` | `{session_ref, username (log only), host, service, ttl_seconds}` | installs 2 priority-200 rules, waits for a barrier, `200` or `4xx/5xx` |
| `POST /policy/revoke` | token | `{session_ref, reason}` or `{all:true, reason}` | deletes the rules by cookie |
| `GET /policy/health`, `/policy/state`, `/policy/flows` | none (localhost, read-only) | – | switch status, grants and per-host state, the switch's real flow table |

Admin API of the auth server (127.0.0.1:5001): `GET /health`, `GET /sessions` (secret-free), `POST /revoke` (`X-Admin-Token`).
