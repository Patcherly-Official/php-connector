<div align="center">

<a href="https://patcherly.com"><img src="https://patcherly.com/assets/img/logo_patcherly_light.png" alt="Patcherly" width="240" /></a>

# Patcherly PHP connector

**Auto-detect and fix production errors in your PHP apps.**
Standalone agent for Laravel, Symfony, and custom PHP — pairs with your Patcherly account.

**For a limited time:** [30-day Pro trial](https://help.patcherly.com/billing/trial/) — no credit card required. Cancel anytime. [Sign up](https://patcherly.com).

[![Packagist patcherly/php-connector](https://img.shields.io/packagist/v/patcherly/php-connector?label=PHP&logo=packagist&logoColor=white&style=flat-square)](https://packagist.org/packages/patcherly/php-connector)
[![Documentation](https://img.shields.io/badge/Documentation-help.patcherly.com-1869f5?style=flat-square)](https://help.patcherly.com/connectors/php/)
[![Discord — join](https://img.shields.io/badge/Discord-join-5865f2?logo=discord&logoColor=white&style=flat-square)](https://discord.gg/7yZkD9KNsS)

> Prefer `@latest` / unpinned Composer installs, or pin from [GitHub Releases](https://github.com/Patcherly-Official/patcherly-connector-packages/releases/latest).

</div>

---

## Recommended install (universal installer)

One command downloads the PHP agent and launches OAuth pairing:

| Platform | Command |
|----------|---------|
| macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/install \| sudo CONNECTOR_TYPE=php bash` |
| Windows PowerShell | `$env:CONNECTOR_TYPE = 'php'; irm "https://api.patcherly.com/install.ps1" \| iex` |

The CLI prints a **verification URL** and a short **user code** — open the URL, sign in, pick your site, and confirm. Credentials are saved to `~/.patcherly/credentials.json` (or `/root/.patcherly/` when run as root). Then start the agent — see [After install](#after-install).

Full installer options (paths, `SKIP_LOGIN`, older versions): [Installing a connector](https://help.patcherly.com/getting-started/installing-connector/).

## Package install (Composer)

```bash
composer global require patcherly/php-connector
patcherly login
```

Then run the long-lived agent (from the package tree or your install directory):

```bash
php patcherly_agent.php
```

Optional on quiet hosts: `patcherly heartbeat` from a daily cron / systemd timer so the connection stays fresh — see the [PHP guide](https://help.patcherly.com/connectors/php/#keep-the-connection-alive-on-quiet-hosts-patcherly-heartbeat).

## Pair later (or re-pair)

| Install method | Command |
|----------------|---------|
| Universal installer (Linux/macOS) | `sudo /opt/patcherly-connector/start.sh login` |
| Universal installer (Windows) | `& "$env:USERPROFILE\patcherly-connector\start.ps1" login` |
| Composer | `patcherly login` |

> On Linux, use `sudo` when the installer enabled the root-run `patcherly-connector` systemd unit so credentials land in `/root/.patcherly/`.

## After install

- Status and approvals: **Sites** in your [Patcherly dashboard](https://app.patcherly.com/targets).
- Start and keep the agent running — on Linux with the universal installer: `systemctl start patcherly-connector`. Otherwise run `start.sh` / `start.ps1`, or `php patcherly_agent.php`. Details: [PHP connector guide](https://help.patcherly.com/connectors/php/).
- Path exclusions and patch policies: [Path rules for sites](https://help.patcherly.com/getting-started/path-exclusion/).

## Test Mode (sample error)

1. In the dashboard: **Sites → your site → Test Mode** ON (30-minute window).
2. On the host:

```bash
patcherly send-test
# or: php patcherly_cli.php send-test
```

Samples are flagged and do not affect metrics or notifications. See [Verify detection with send-test](https://help.patcherly.com/connectors/php/#verify-detection-end-to-end-with-patcherly-send-test).

## Context consent

Default is **full**. Change with:

```bash
patcherly context get
patcherly context set full|minimal|off
patcherly context upload
```

Env override: `PATCHERLY_CONTEXT_CONSENT`.

## Security

OAuth pairing and per-token **HMAC signing**; fix payloads are verified before apply. Built-in redaction runs before ingest; you can add custom sanitizer patterns per site.

- [Connectors overview](https://help.patcherly.com/connectors/overview/)
- [PHP connector — HMAC](https://help.patcherly.com/connectors/php/#hmac-signing)
- [Prompt injection protection](https://help.patcherly.com/security/prompt-injection-protection/)
- [Custom sanitizer patterns](https://help.patcherly.com/security/custom-sanitizer-patterns/)
- [Post-apply restart safety](https://help.patcherly.com/security/post-apply-restart-safety/)
- [Hardening: backup folders](https://help.patcherly.com/connectors/overview/#hardening-backup-folders-and-the-public-web)

## Documentation & support

- **[PHP connector guide](https://help.patcherly.com/connectors/php/)** — install, systemd/cron, troubleshooting
- **[Connectors overview](https://help.patcherly.com/connectors/overview/)** · **[All connectors](https://github.com/Patcherly-Official/patcherly-connector-packages#readme)**
- **[Discord](https://discord.gg/7yZkD9KNsS)** · **[Dashboard](https://app.patcherly.com)** · **[Report a bug](https://github.com/Patcherly-Official/patcherly-connector-packages/issues)**

## License

[MIT](LICENSE)

Using the **Patcherly service** is governed by our [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use) policy. Official product support applies only to **unmodified** connector releases from our official sources.
