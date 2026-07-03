# Patcherly PHP connector

Patcherly detects bugs in real time in your app. It creates a customized AI patch, and once you approve it, backs up your code, fixes it & tests the patch for you. If anything is off, it rolls back the changes automatically, or you can always roll it back in a click.

**[patcherly.com](https://patcherly.com)** · **[PHP connector docs](https://help.patcherly.com/connectors/php/)**

## Recommended install

Use the [universal installer](https://help.patcherly.com/getting-started/installing-connector/) (one command, auto-pairs).

## Package install

```bash
composer global require patcherly/php-connector
patcherly login
```

## Pairing

```bash
patcherly login
```

## Test ingest

After pairing, verify the pipeline without waiting for a real exception. In your [Patcherly dashboard](https://app.patcherly.com/targets), open **Targets → your target → Test Mode** (30-minute window per target), then run:

```bash
patcherly send-test
```

The sample is tagged `is_test_sample` — it does not affect metrics or notifications. See [Verify ingest with send-test](https://help.patcherly.com/connectors/php/#verify-ingest-end-to-end-with-patcherly-send-test) in the help center.

## Security

OAuth pairing and per-token **HMAC signing**; fix payloads verified before apply. See [Connectors overview](https://help.patcherly.com/connectors/overview/), [Prompt injection protection](https://help.patcherly.com/security/prompt-injection-protection.md), and [Custom sanitiser patterns](https://help.patcherly.com/security/custom-sanitizer-patterns.md). PHP-specific detail: [PHP connector — security](https://help.patcherly.com/connectors/php/#hmac-signing).

## Documentation

- [PHP connector guide](https://help.patcherly.com/connectors/php/)
- [All connectors (releases & source)](https://github.com/Patcherly-Official/patcherly-connector-packages#readme)

## Support

- [Report a bug](https://github.com/Patcherly-Official/patcherly-connector-packages/issues)

## License

[MIT](LICENSE)
