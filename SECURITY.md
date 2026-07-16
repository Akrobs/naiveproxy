# Security Policy

## Reporting Security Issues

Please do not open a public issue with secrets, private server addresses,
subscription URLs, bot tokens, SSH keys, or production configuration files.

For a security report, use the repository owner contact channel configured in
the project profile, or create a minimal public issue that says a private
security report is needed without including sensitive details.

## Do Not Publish

Never attach or paste:

- `/etc/naiveproxy/naive.conf`
- `/etc/naiveproxy/users.conf`
- `/etc/naiveproxy/users.d/*`
- `/etc/naiveproxy/subscriptions/*`
- `/etc/naiveproxy/nodes.conf`
- Telegram bot tokens
- Cloudflare/WARP credentials
- SSH private keys
- real customer subscription URLs

## If a Secret Leaks

Rotate the affected credential immediately:

- Telegram bot token: revoke it in BotFather and install a new token.
- Subscription URL: run `subscription-reset USER`.
- SSH key: remove the public key from servers and issue a new key.
- Server user password: rotate the user password and rebuild subscriptions.

## Hardening Baseline

Production servers should use:

- SSH key-only login
- root login disabled
- UFW deny-by-default
- Fail2Ban or CrowdSec
- automatic security updates
- least-open ports
- encrypted backups with restore checks

## Safe Updates and Imports

- Import only backups created by Yurich Panel and keep the pre-import export until the restored server is verified.
- Do not disable SHA256 checks for self-update or protocol binaries in production.
- Build Caddy with the pinned release and full `forwardproxy` commit; verify `http.handlers.forward_proxy` before replacement.
- Keep `/etc/naiveproxy/*.conf`, bot order files and PingTunnel environment files owned by `root` with mode `600`.
- After an update or import, run `bash -n`, `safe-apply`, `health`, `protocol-validate` and a three-round `protocol-benchmark` before removing rollback files.
- Use `ssh-rescue` only from a provider console. It requires a working systemd auto-disable timer and defaults to a 30-minute emergency window.

## Remaining Trust Boundaries

- The public self-update checksum protects integrity in transit, but it is hosted with the script. For independent authenticity, publish signed release manifests with an offline maintainer key.
- Protocol services currently require privileged migration testing before they can safely run as dedicated non-root users.
- First-time node SSH trust is interactive. Compare the displayed fingerprint with the provider console before entering `TRUST`.
- Test every release on one Ubuntu canary node before fleet rollout; Windows static checks do not replace systemd, UFW, Unbound, Caddy, Xray and Hysteria integration tests.
