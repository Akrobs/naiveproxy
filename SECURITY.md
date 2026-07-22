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
- `/etc/naiveproxy/credentials/private.pem`
- `/etc/naiveproxy/credentials/users.secrets`
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

## Proxy Credential Storage

- `/etc/naiveproxy/users.conf` contains only bcrypt records after migration.
- Caddy uses its standard `basic_auth bcrypt` verifier; plaintext proxy passwords are not written to `Caddyfile`.
- Hysteria 2 uses a root-owned command verifier against `/etc/naiveproxy/credentials/users.active.htpasswd`; passwords are read from stdin and are not passed in process arguments.
- Hysteria 2 never reads TLS material directly from `/root`. A validated copy is kept in `/etc/naiveproxy/hysteria-tls` with directory/file modes `700/600`, and a hardened timer synchronizes Caddy renewals.
- Reversible client secrets are RSA-OAEP-SHA256 encrypted in `/etc/naiveproxy/credentials/users.secrets`. The RSA private key is `root:root` mode `600`.
- The vault protects against accidental plaintext disclosure. It does not protect against a root compromise because the ciphertext and decryption key are on the same host.
- Generated subscription documents contain working client credentials by design. Treat every subscription URL and generated profile as a bearer secret, keep `Cache-Control: no-store`, and rotate both the password and subscription token after a leak.
- State exports include the vault private key and must be stored like passwords. Prefer the encrypted `backup` command for off-host copies.

Check and migrate an existing installation:

```bash
sudo bash yurich-panel.sh credentials-status
sudo bash yurich-panel.sh backup
sudo bash yurich-panel.sh credentials-migrate
sudo bash yurich-panel.sh security-audit
sudo bash yurich-panel.sh hysteria-repair
```

Do not delete the pre-migration backup until NaiveProxy, Hysteria 2 and subscription refresh have all been tested.

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
