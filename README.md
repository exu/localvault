# localvault

Local secret vault. No server, no auth service. Unlock with a password (Touch ID planned, see PLAN.md).

## Install

    make build                                          # dist/localvault
    install -m 0755 dist/localvault ~/.local/bin/       # any dir on PATH

## Quick start

    localvault configure                  # first time: create vault, set password
    localvault unlock                     # start a 15m session
    localvault set API_TOKEN=abc123       # store a secret
    localvault get API_TOKEN              # prints abc123
    localvault lock                       # end the session

## Commands

| Command | What it does |
|---|---|
| `configure [--with NAME]` | Create the vault (password unlocker). On an existing vault, adds or replaces the named unlocker; asks for your current password first. |
| `unlock [--with NAME] [--ttl 15m]` | Authenticate and start a session. `--ttl` takes Go durations: `30s`, `15m`, `2h`. |
| `set KEY=val [KEY=val ...]` | Store or update secrets. `KEY=-` reads the value from stdin. |
| `get KEY` | Print the value. Exits nonzero if the key is missing. |
| `list` | Print secret names, sorted. |
| `delete KEY` | Remove a secret. |
| `run 'COMMAND'` | Run a shell command with `$env[KEY]` references resolved. |
| `status` | Show `locked` or `unlocked, <time> left`. |
| `lock` | End the session immediately. |

Global flag: `--no-prompt` fails when locked instead of asking for the password.

## Examples

Keep a secret out of shell history:

    printf '%s' "$TOKEN" | localvault set API_TOKEN=-
    pbpaste | localvault set API_TOKEN=-

Use a secret in a command without it appearing in `ps`:

    localvault run 'curl -H "Authorization: Bearer $env[API_TOKEN]" https://example.com'

Each `$env[NAME]` becomes an environment variable of the child shell, so use it like a normal `$NAME` (quote it yourself).

Read into a variable in a script:

    token=$(localvault get API_TOKEN) || exit 1

Fail fast in CI or scripts instead of prompting:

    localvault get API_TOKEN --no-prompt

## Unlock prompts and AI agents

When the vault is locked, `get`, `set`, `list`, `delete` and `run` start an unlock themselves:

- stdin is a terminal: prompt in the terminal.
- no terminal (for example an AI agent running the command): a native macOS dialog opens. It names the requesting process and the command (key names only, never values) and the session length.
- Cancelling the dialog, or 60 seconds without an answer, fails the command with `unlock cancelled`.
- `LOCALVAULT_PROMPT=gui|tty` forces one kind of prompt.

An agent can read secrets through `get` and `run` while a session is live, so keep the TTL short and run `localvault lock` when done.

## Files and environment

| Path / variable | Purpose |
|---|---|
| `~/.localvault/vault.lv` | Encrypted vault (0600). |
| `~/.localvault/session` | Session key and expiry while unlocked (0600). |
| `LOCALVAULT_DIR` | Use a different vault directory (handy for testing). |
| `LOCALVAULT_PROMPT` | `gui` or `tty` to force the password prompt kind. |

## Design

- Random 32-byte key (DEK) encrypts the vault with XChaCha20-Poly1305.
- Each unlocker stores its own wrapped DEK in the vault header; add or remove unlockers without re-encrypting.
- Password unlocker: argon2id (512 MiB, ~250ms per guess) derives the wrapping key. The unlocker list is authenticated, so stripping or swapping entries breaks decryption.
- Unlockers are pluggable: implement `unlocker.Unlocker` and call `unlocker.Register`.
- `unlock` writes the DEK plus an expiry to `~/.localvault/session` (0600) until the TTL ends.

## Threat model

Protects secrets at rest. Out of scope: malware running as your user (can read the session file while unlocked), root, memory dumps. Keep TTLs short and `lock` when done.
