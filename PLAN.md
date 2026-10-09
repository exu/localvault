# localvault plan

Local secret vault. No auth service. Unlock with password or macOS Touch ID.

## Decisions
- Session: plain session file, no daemon. `unlock` writes DEK + expiry to a 0600 file in a 0700 user dir; `get`/`set` read it, delete when expired.
- Touch ID: Keychain item with biometry access control, signed binary. No weaker LAContext-only fallback.
- Repo: private, exu/localvault.

## Crypto
- Random 32-byte DEK encrypts the vault (XChaCha20-Poly1305, one JSON blob of KEY: val).
- Each unlocker stores its own wrapped DEK in the vault header. Add/remove unlocker without re-encrypting secrets.
- password: argon2id KEK (salt + params in header) wraps DEK.
- touchid: KEK in biometry-protected Keychain item wraps DEK.
- Files in ~/.localvault/: vault.lv (header + ciphertext). Session file in a per-user 0700 dir.

## Pluggable unlocker
```go
type Unlocker interface {
    Name() string
    Enroll(dek []byte) (Blob, error)
    Unlock(Blob) ([]byte, error)
    Available() bool
}
```
Registry via `Register()` in `init()`. `touchid` behind darwin build tag, stub elsewhere.

## Commands
- `configure`: create vault, set password, optionally enroll Touch ID. Re-run to add/replace unlocker.
- `set KEY=val [...]`: upsert; `KEY=-` reads value from stdin.
- `unlock [--with password|touchid] [--ttl 15m]`: default touchid if enrolled, else password.
- `get KEY`: print value; nonzero exit if missing or locked.
- Later: `list`, `delete`, `lock`, `run 'cmd $env[K]'`.

## Risks
- Touch ID Keychain biometry ACL usually needs Data Protection keychain: signed binary + entitlements (-34018 if unsigned). Spike first; sign in Makefile.
- Session file holds DEK in plaintext until TTL. Same-UID malware and root are out of scope; document in README.

## Milestones
- [x] 0. Repo + scaffold
- [x] 1. vault package: format, seal/open, multi-wrapped-key header, tests
- [x] 2. Unlocker interface, registry, password unlocker (argon2id), tests
- [x] 3. configure, set, get
- [x] 4. Session file, unlock, lock, status, TTL
- [ ] 5. Touch ID spike, then touchid unlocker (cgo, darwin tag), signing in Makefile
- [ ] 6. README threat model, release, optional run/list/delete
