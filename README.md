# localvault

Local secret vault. No server, no auth service. Unlock with a password (Touch ID planned, see PLAN.md).

## Build

    make build        # dist/localvault

## Usage

    localvault configure                 # create vault, set password
    localvault configure --with <name>   # add/replace another unlocker
    localvault unlock [--with <name>] [--ttl 15m]
    localvault set KEY=val [KEY=val ...] # KEY=- reads the value from stdin
    localvault get KEY
    localvault list
    localvault delete KEY
    localvault run 'curl -H "Authorization: $env[TOKEN]" https://example.com'
    localvault status
    localvault lock

`run` exposes each `$env[NAME]` as an environment variable of the child shell, so values never appear in `ps` output.

Vault lives in `~/.localvault` (override with `LOCALVAULT_DIR`).

## Design

- Random 32-byte key (DEK) encrypts the vault with XChaCha20-Poly1305.
- Each unlocker stores its own wrapped DEK in the vault header; add or remove unlockers without re-encrypting.
- Password unlocker: argon2id derives the wrapping key.
- Unlockers are pluggable: implement `unlocker.Unlocker` and call `unlocker.Register`.
- `unlock` writes the DEK plus an expiry to `~/.localvault/session` (0600) until the TTL ends.

## Threat model

Protects secrets at rest. Out of scope: malware running as your user (can read the session file while unlocked), root, memory dumps. Keep TTLs short and `lock` when done.
