<?php
/**
 * sanitizer_vendor_tokens_test.php
 *
 * Phase 2.3 / V3 — verifies the high-signal vendor-token patterns added to
 * the standalone PHP connector sanitizer (connectors/php/sanitizer.php) in
 * v1.47:
 *
 *   - AWS access key IDs (AKIA* / ASIA*)
 *   - GitHub tokens (ghp_ / gho_ / ghu_ / ghs_ / ghr_)
 *   - Slack tokens (xoxb-, xoxp-, xoxa-, xapp-)
 *   - Stripe keys (sk_live_, sk_test_, rk_live_, rk_test_, pk_*, whsec_)
 *   - Extended connection-string schemes (amqp, clickhouse, mssql, oracle,
 *     jdbc:*)
 *   - OpenSSH public-key blobs
 *   - PEM-armored private-key blocks (OPENSSH / RSA / DSA / EC / PKCS#8)
 *
 * Each case confirms (a) the secret value no longer appears in the sanitized
 * output, and (b) a deterministic placeholder marker is present.
 *
 * Run: php connectors/php/tests/sanitizer_vendor_tokens_test.php
 */

declare(strict_types=1);

error_reporting(E_ALL & ~E_DEPRECATED);

require_once __DIR__ . '/../sanitizer.php';

use Patcherly\Connector\Sanitizer;

$failures = [];

function _check(string $label, string $raw, string $secret, string $marker, array &$failures): void {
    $out = Sanitizer::sanitizeLogLineForIngest($raw);
    if (strpos($out, $secret) !== false) {
        $failures[] = "[{$label}] secret leaked — {$secret} still in output: {$out}";
        return;
    }
    if (strpos($out, $marker) === false) {
        $failures[] = "[{$label}] marker missing — expected {$marker} in output: {$out}";
    }
}

function _check_unchanged(string $label, string $raw, string $expectedSubstring, array &$failures): void {
    $out = Sanitizer::sanitizeLogLineForIngest($raw);
    if (strpos($out, $expectedSubstring) === false) {
        $failures[] = "[{$label}] expected substring NOT preserved: {$expectedSubstring} (got: {$out})";
    }
}

// ---- AWS access keys ------------------------------------------------------

_check(
    'aws_akia',
    'AccessDenied for AKIAIOSFODNN7EXAMPLE on s3',
    'AKIAIOSFODNN7EXAMPLE',
    'AWS_ACCESS_KEY_ID_REDACTED',
    $failures
);
_check(
    'aws_asia',
    'sts/ASIAY34F0R7EXAMPLE12/expired',
    'ASIAY34F0R7EXAMPLE12',
    'AWS_ACCESS_KEY_ID_REDACTED',
    $failures
);
_check_unchanged(
    'aws_random_uppercase_left_alone',
    'call ABCDEFGHIJKL12345678 ok',
    'ABCDEFGHIJKL12345678',
    $failures
);

// ---- GitHub tokens --------------------------------------------------------

_check(
    'gh_pat_classic',
    'git fetch ' . 'ghp_' . str_repeat('a', 36),
    'ghp_' . str_repeat('a', 36),
    'GITHUB_TOKEN_REDACTED',
    $failures
);
_check(
    'gh_oauth',
    'token=' . 'gho_' . str_repeat('B', 40),
    'gho_' . str_repeat('B', 40),
    'GITHUB_TOKEN_REDACTED',
    $failures
);
_check(
    'gh_server_to_server',
    'App token ' . 'ghs_' . str_repeat('9', 36) . ' expired',
    'ghs_' . str_repeat('9', 36),
    'GITHUB_TOKEN_REDACTED',
    $failures
);
_check_unchanged(
    'gh_short_left_alone',
    'x=ghp_short',
    'ghp_short',
    $failures
);

// ---- Slack tokens ---------------------------------------------------------

_check(
    'slack_bot_token',
    'slack post failed token=xoxb-1234567890-1234567890-abcdefABCDEF',
    'xoxb-1234567890-1234567890-abcdefABCDEF',
    'SLACK_TOKEN_REDACTED',
    $failures
);
_check(
    'slack_user_token',
    'xoxp-0987654321-1122334455-abcDEFghi123',
    'xoxp-0987654321-1122334455-abcDEFghi123',
    'SLACK_TOKEN_REDACTED',
    $failures
);

$xapp = 'xapp-1-A012345678-1234567890-abcdef0123456789';
$xappOut = Sanitizer::sanitizeLogLineForIngest($xapp);
if (strpos($xappOut, $xapp) !== false) {
    $failures[] = "[slack_xapp] secret leaked: {$xappOut}";
} elseif (strpos($xappOut, 'SLACK_TOKEN_REDACTED') === false && strpos($xappOut, 'SLACK_APP_TOKEN_REDACTED') === false) {
    $failures[] = "[slack_xapp] no slack marker in: {$xappOut}";
}

// ---- Stripe keys ----------------------------------------------------------

_check(
    'stripe_sk_live',
    'Stripe::AuthenticationError ' . 'sk_live_' . str_repeat('A', 32),
    'sk_live_' . str_repeat('A', 32),
    'STRIPE_SECRET_KEY_REDACTED',
    $failures
);
_check(
    'stripe_rk_test',
    'rk_test_' . str_repeat('z', 28),
    'rk_test_' . str_repeat('z', 28),
    'STRIPE_SECRET_KEY_REDACTED',
    $failures
);
_check(
    'stripe_publishable',
    'leaked ' . 'pk_live_' . str_repeat('p', 24),
    'pk_live_' . str_repeat('p', 24),
    'STRIPE_PUBLISHABLE_KEY_REDACTED',
    $failures
);
_check(
    'stripe_webhook_secret',
    'sig verify failed for ' . 'whsec_' . str_repeat('W', 32),
    'whsec_' . str_repeat('W', 32),
    'STRIPE_WEBHOOK_SECRET_REDACTED',
    $failures
);
_check_unchanged(
    'stripe_unknown_prefix_left_alone',
    'sk_demo_short',
    'sk_demo_short',
    $failures
);

// ---- Connection strings ---------------------------------------------------

$amqpOut = Sanitizer::sanitizeLogLineForIngest('connect amqp://celery:Hunter2@rabbit:5672/celery');
if (strpos($amqpOut, 'Hunter2') !== false) {
    $failures[] = "[amqp] password leaked: {$amqpOut}";
}
if (strpos($amqpOut, 'amqp://USERNAME_REDACTED:PASSWORD_REDACTED@rabbit:5672/celery') === false) {
    $failures[] = "[amqp] expected normalised form missing: {$amqpOut}";
}

$chOut = Sanitizer::sanitizeLogLineForIngest('clickhouses://reader:topSecretPwd@ch.internal:9440');
if (strpos($chOut, 'topSecretPwd') !== false) {
    $failures[] = "[clickhouse] password leaked: {$chOut}";
}
if (strpos($chOut, 'clickhouses://USERNAME_REDACTED:PASSWORD_REDACTED@') === false) {
    $failures[] = "[clickhouse] expected normalised form missing: {$chOut}";
}

$jdbcOut = Sanitizer::sanitizeLogLineForIngest('jdbc:mysql://app:Secret123@db:3306/db_prod');
if (strpos($jdbcOut, 'Secret123') !== false) {
    $failures[] = "[jdbc] password leaked: {$jdbcOut}";
}
if (strpos($jdbcOut, 'jdbc:mysql://USERNAME_REDACTED:PASSWORD_REDACTED@') === false) {
    $failures[] = "[jdbc] expected normalised form missing: {$jdbcOut}";
}

// ---- SSH public keys ------------------------------------------------------

$rsaBlob =
    'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLkR6X4w7q1+e9Y6X9Lp' .
    'kxQGfYrYJ9d5Vp0w0xN3J7r2P9YxTzM8aZxK1Tg5+JaB1z2NkPq5Bk5L2' .
    ' operator@host';
$rsaOut = Sanitizer::sanitizeLogLineForIngest($rsaBlob);
if (strpos($rsaOut, 'AAAAB3NzaC1yc2EAAAADAQABAAABAQDLkR6X4w7q1+e9Y6X9Lp') !== false) {
    $failures[] = "[ssh_rsa] key blob leaked: {$rsaOut}";
}
if (strpos($rsaOut, 'SSH_PUBLIC_KEY_REDACTED') === false) {
    $failures[] = "[ssh_rsa] marker missing: {$rsaOut}";
}

$edBlob = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzfFq8nP9Yp1F9X3ZqzYx6r7Pq+TxYxZ user';
$edOut = Sanitizer::sanitizeLogLineForIngest($edBlob);
if (strpos($edOut, 'AAAAC3NzaC1lZDI1NTE5') !== false) {
    $failures[] = "[ssh_ed25519] key blob leaked: {$edOut}";
}
if (strpos($edOut, 'SSH_PUBLIC_KEY_REDACTED') === false) {
    $failures[] = "[ssh_ed25519] marker missing: {$edOut}";
}

// ---- PEM-armored private keys --------------------------------------------
//
// v1.47 plan-recheck follow-up — pins the `-----BEGIN [A-Z ]*PRIVATE KEY-----`
// multi-line pattern. The pattern was in production since v1.47 V3 but had no
// regression test, and the original `[A-Z ]+` quantifier silently skipped
// PKCS#8 unencrypted keys (`-----BEGIN PRIVATE KEY-----` with no algorithm
// prefix). Fixed to `[A-Z ]*` so PKCS#8 is also redacted.

$opensshBlock =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n" .
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" .
    "QyNTUxOQAAACBzfFq8nP9Yp1F9X3ZqzYx6r7PqTxYxZSampleSampleSampleSamplexx\n" .
    "-----END OPENSSH PRIVATE KEY-----";
$opensshOut = Sanitizer::sanitizeLogLineForIngest("connect failed:\n{$opensshBlock}\n(end)");
if (strpos($opensshOut, 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmU') !== false) {
    $failures[] = "[private_key_openssh] key material leaked: {$opensshOut}";
}
if (strpos($opensshOut, 'PRIVATE_KEY_REDACTED') === false) {
    $failures[] = "[private_key_openssh] marker missing: {$opensshOut}";
}

$rsaBlockPriv =
    "-----BEGIN RSA PRIVATE KEY-----\n" .
    "MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" .
    "-----END RSA PRIVATE KEY-----";
$rsaPrivOut = Sanitizer::sanitizeLogLineForIngest($rsaBlockPriv);
if (strpos($rsaPrivOut, 'MIIEowIBAA') !== false) {
    $failures[] = "[private_key_rsa] key material leaked: {$rsaPrivOut}";
}
if (strpos($rsaPrivOut, 'PRIVATE_KEY_REDACTED') === false) {
    $failures[] = "[private_key_rsa] marker missing: {$rsaPrivOut}";
}

$pkcs8Block =
    "-----BEGIN PRIVATE KEY-----\n" .
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDLkR6X4w7q1+e9\n" .
    "-----END PRIVATE KEY-----";
$pkcs8Out = Sanitizer::sanitizeLogLineForIngest($pkcs8Block);
if (strpos($pkcs8Out, 'MIIEvgIBADANBgkqhkiG') !== false) {
    $failures[] = "[private_key_pkcs8] key material leaked: {$pkcs8Out}";
}
if (strpos($pkcs8Out, 'PRIVATE_KEY_REDACTED') === false) {
    $failures[] = "[private_key_pkcs8] marker missing: {$pkcs8Out}";
}

$encryptedBlock =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" .
    "AAAAYourEncryptedPrivateKeyMaterialGoesHereOnMultipleLinesAAAA\n" .
    "-----END ENCRYPTED PRIVATE KEY-----";
$encryptedOut = Sanitizer::sanitizeLogLineForIngest($encryptedBlock);
if (strpos($encryptedOut, 'AAAAYourEncryptedPrivateKey') !== false) {
    $failures[] = "[private_key_encrypted] key material leaked: {$encryptedOut}";
}
if (strpos($encryptedOut, 'PRIVATE_KEY_REDACTED') === false) {
    $failures[] = "[private_key_encrypted] marker missing: {$encryptedOut}";
}

$unmatchedOut = Sanitizer::sanitizeLogLineForIngest(
    "-----BEGIN OPENSSH PRIVATE KEY-----\n(operator pasted partial dump)\nstack trace follows"
);
if (strpos($unmatchedOut, 'stack trace follows') === false) {
    $failures[] = "[private_key_unmatched_fence_eats_context] context lost: {$unmatchedOut}";
}

// ---- Placeholder doesn't echo secret --------------------------------------

$leakSecret = 'ghp_' . str_repeat('X', 40);
$leakOut = Sanitizer::sanitizeLogLineForIngest($leakSecret);
if (strpos($leakOut, 'XXXX') !== false) {
    $failures[] = "[placeholder_no_back_reference_leak] back-reference leak: {$leakOut}";
}

// ---- Report ---------------------------------------------------------------

if (!empty($failures)) {
    fwrite(STDERR, "FAIL — " . count($failures) . " case(s):\n");
    foreach ($failures as $f) {
        fwrite(STDERR, "  - {$f}\n");
    }
    exit(1);
}

echo "OK — all vendor-token sanitizer cases passed (PHP standalone)\n";
exit(0);
