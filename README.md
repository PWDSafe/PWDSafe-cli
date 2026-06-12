# pwdsafe-cli

A terminal client for [PWDSafe](https://github.com/PWDSafe/PWDSafe), a
self-hosted password manager. It provides both an interactive TUI and a
set of subcommands for browsing groups, viewing credential metadata,
decrypting and copying passwords to the clipboard, and managing
credentials and groups.

## Requirements

- A running PWDSafe server, **version 3.2 or later** (this client relies
  on API endpoints and vault key derivation introduced in 3.2).

## Usage

```
pwdsafe-cli                              launch the interactive TUI
pwdsafe-cli tui                          launch the interactive TUI
pwdsafe-cli login [--url <url>] [--email <email>]
pwdsafe-cli groups
pwdsafe-cli groups create <name> [--parent <group-id>]
pwdsafe-cli add <group-id>
pwdsafe-cli move <credential-id> <group-id>
pwdsafe-cli list [group-id]
pwdsafe-cli show <credential-id> [--copy]
pwdsafe-cli devices
pwdsafe-cli logout
```

On first run, `pwdsafe-cli login` will prompt for the server URL, email,
password, and (if enabled) a two-factor code. The session token and
encrypted vault key material are stored locally so subsequent commands
don't require logging in again.

## Building

```
go build -o pwdsafe-cli .
```

Requires Go 1.25 or later.
