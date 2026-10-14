---
name: localvault
description: Install and use localvault, a local secret vault, so commands can use API keys, tokens and passwords without the values ever appearing in the conversation. Use when a task needs a credential, when the user mentions localvault or storing secrets, or before asking the user to paste a secret.
compatibility: macOS or Linux, amd64 or arm64. Needs a graphical session or a terminal for the unlock password prompt.
metadata:
  repo: https://github.com/exu/localvault
---

# localvault

localvault keeps secrets in an encrypted local vault. `localvault run` injects them into a command as environment variables and scrubs every stored value from the command's output, so values stay out of the transcript. You see secret names, never values.

## 1. Check it is installed

```bash
command -v localvault && localvault --version
```

If missing, install it (prefer Homebrew, else the checksum-verifying script):

```bash
brew install exu/tap/localvault
# or
curl -fsSL https://raw.githubusercontent.com/exu/localvault/main/install.sh | sh
```

The script installs to `~/.local/bin` (set `INSTALL_DIR` to change it). If `localvault` is still not found, tell the user to add that directory to `PATH`.

If there is no vault yet (`localvault status` or `list` says "no vault"), ask the user to run `localvault configure` in their own terminal. It asks them to choose a password. Never choose or ask for their password yourself.

## 2. See what is available

```bash
localvault status        # locked or unlocked, time left
localvault list --no-prompt
```

`list` prints secret names only. Use `--no-prompt` when you only want to check state: it fails with "locked" instead of opening a password dialog.

## 3. Use a secret

Write `$env[NAME]` where the value belongs and run the command through `localvault run`:

```bash
localvault run 'curl -H "Authorization: Bearer $env[API_TOKEN]" https://api.example.com'
localvault run 'helm upgrade app ./chart --set token=$env[API_TOKEN]'
```

- `$env[NAME]` becomes an environment variable of the child shell. Quote it yourself where the shell needs it.
- Stored values in stdout and stderr are replaced with `[REDACTED:NAME]`.
- If the command writes output to a file, that file is not redacted. Do not read such files back, and delete them when done.

## 4. If the vault is locked

`run`, `list`, `set`, `get` and `delete` open a password dialog on the user's screen when the vault is locked. It names the requesting process and command and starts a 15 minute session. Tell the user a dialog is coming if they might not expect it, and wait for it.

- "unlock cancelled": the user dismissed the dialog or it timed out after 60 seconds. Ask the user whether to retry. Do not loop.
- No dialog possible (headless machine, no display): ask the user to run `localvault unlock` in a terminal.
- `localvault unlock --ttl 1h` starts a longer session if the user wants one.

## 5. If a secret is missing

Ask the user to store it themselves, in their own terminal, so the value never passes through you:

```bash
pbpaste | localvault set NAME=-        # macOS clipboard
localvault set NAME=value              # or typed directly
```

## Rules

- Never run `localvault get`. It prints the raw value into the conversation. Use `run`.
- Never read, copy or print files in `~/.localvault/` (vault and session file).
- Never fetch a credential from another store (a Kubernetes Secret, another password manager, an env dump) to work around a missing secret. Ask the user to store it.
- Never print the environment (`env`, `printenv`, `set`) inside `run` to inspect secrets, and do not try to encode or split a value to get around redaction.
- Redaction matches literal values only. A very short secret value also masks matching text in unrelated output.
- Keep sessions short and run `localvault lock` when the task is done if the user asked for that.

## Quick reference

| Command | Purpose |
|---|---|
| `localvault run 'cmd $env[NAME]'` | run with secrets injected and output redacted |
| `localvault list` | secret names |
| `localvault status` | session state |
| `localvault set NAME=-` | store a secret (user runs it) |
| `localvault unlock [--ttl 15m]` | start a session |
| `localvault lock` | end the session |

Full docs: https://localvault.wyso.cc
