Jaynshare client kit

This archive is the client half of a Jaynshare release: the client
executable for each supported platform and the installer that enrols this
machine with a pool. Your operator packages it into an enrollment bundle
for you; you never use the kit directly.

Prerequisite: Claude Code must already be installed on this machine; the
pool serves Claude Code; it never installs it or replaces your own login.

To enrol, extract the bundle you received into an empty directory, open a
terminal in that directory and run its installer. On macOS:

  /bin/sh ./install-macos.sh

On Windows, from PowerShell or the Command Prompt:

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install-windows.ps1

The bypass applies to that one PowerShell process and changes no machine
or user policy. If PowerShell still refuses the script, a policy managed by
your organisation forbids it, and that setup is not supported.

The installer shows the client id, the display name, both server origins,
the pending expiry, the CA fingerprints (the interception CA and, for an
HTTPS base URL, the base-URL CA) and the release, then asks for your
confirmation and reads the one-time enrollment code at a hidden prompt. Your
operator sends the code separately from the bundle; enter it only there.

Members:
  release.json, release.json.minisig, SHA256SUMS   the signed release set
  install-*.sh|ps1, uninstall-*.sh|ps1            the installers
  payload/<platform>/jaynshare[.exe]              the client executable

Using the pool

Once enrolled, run `jaynshare claude` wherever you would have run Claude
Code. It starts a picker when the pool cannot choose for you: pick the
account to serve this session and it is remembered for it. Pass
`--account <name>` to name the account yourself, or `--auto` to let the
pool pick without asking. `--direct` runs outside the pool entirely,
under your own login instead of a pool account.

`jaynshare status` shows this machine's enrollment and connection state.
If you want plain `claude` to keep working, `jaynshare alias` makes it
run the pool client.

A private address never provides encryption. If the base URL is
plain HTTP, the client secret and request content travel in clear on the
private network (the CONNECT proxy exposes its proxy credential there);
your operator mitigates this with TLS on the base URL's listener and by
keeping the pool's network segmented.

What does not work through the pool

Claude Code's Remote Control and other account-bound features do not
work through the pool, in either mode. A warning about connectors at
startup is expected: it means the pool's gateway credential is in use,
not that something is broken. Your own Claude login is never used, read
or relayed by the pool; only the enrolled client identity travels.

If a prompt fails with a proxy-tunnel error

Claude Code reports a revoked credential as a proxy-tunnel error. After
a revocation, run `jaynshare status`: it names the enrollment state and
tells you whether this machine is still enrolled.

What the server records

For every request the server writes one audit record, with these fields
by name:

  timestamp, duration_ms, principal (your client id),
  source_address (the address your request came from), session_id,
  method, path (without the query string), model, serving_account,
  no_service_reason, selection_cause, status, attempts, failed_over,
  error_class, pinned, mode, blocked_pattern.

The record never contains a credential, and never a request or response
body. The source address is recorded as described above.

Wire capture

Request and response bodies are recorded only while wire capture is on.
`jaynshare status` and the status line always show whether wire capture
is currently on.
