# CipherNote MCP

CipherNote MCP is a small, local-first notebook for MCP-compatible AI clients.
Titles, note bodies, and tags are encrypted at rest with AES-256-GCM before
they enter SQLite. The server exposes five tools: write, search, read, list
recent notes, and delete.

This repository contains **no user notes, databases, keys, server addresses,
logs, or telemetry**. It starts with an empty database on every installation.

## Privacy model

- Notes stay on the machine where this server runs.
- No analytics, network sync, or remote API calls are implemented.
- The encryption key is read from the environment and is never stored in the
  database.
- Titles, bodies, and tags are encrypted. Note IDs, timestamps, importance,
  and ciphertext sizes remain visible to someone who can read the database.
- Search happens locally after decryption in memory.
- Credential-like content is rejected to discourage using a notebook as a
  password manager.

This protects a copied database, not a compromised running computer. A process
that can read `CIPHERNOTE_KEY` or inspect the running process can read notes.

## Install

Requirements: Node.js 20+, Python 3.10+, and `python` available on `PATH`.

```sh
npm install
python -m venv .venv
```

Activate the virtual environment, then install the Python dependency:

```sh
python -m pip install -r requirements.txt
python scripts/generate_key.py
```

Copy the generated value into the environment as `CIPHERNOTE_KEY`. Do not put
the real value in Git. Optionally set `CIPHERNOTE_DB` to choose the database
location.

## MCP client configuration

Use an absolute path to `src/server.js`. Keep the real key in your client-side
secret store where possible.

```json
{
  "mcpServers": {
    "ciphernote": {
      "command": "node",
      "args": ["/absolute/path/to/ciphernote-mcp/src/server.js"],
      "env": {
        "CIPHERNOTE_KEY": "base64:YOUR_KEY"
      }
    }
  }
}
```

Run directly with `npm start`. The server uses stdio, so protocol messages are
written to stdout and diagnostics to stderr.

## Backup and key loss

Back up the database and encryption key separately. Without the exact key,
encrypted notes cannot be recovered. Never commit either item. SQLite may
create `-wal` and `-shm` files while running; include them in a consistent
backup or stop the server before copying the database.

## Development

```sh
python -m pip install -r requirements.txt
npm test
```

See [SECURITY.md](SECURITY.md) for the threat model and vulnerability reports.

