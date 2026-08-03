<?php
/**
 * Unwrap FastAPI/HTTP error bodies for connector soft-stops.
 * Prefer nested detail.code; fall back to top-level code.
 */

declare(strict_types=1);

/** @var list<string> */
const PATCHERLY_FIX_APPROVE_STATUSES = ['awaiting_approval', 'manual_review_required'];

/** @var list<string> */
const PATCHERLY_APPROVE_409_SOFT_STOP_CODES = [
    'empty_fix',
    'error_path_blocked',
    'low_confidence_confirmation_required',
    'auto_apply_not_enabled',
    'approve_requires_post_analysis',
];

/**
 * @param mixed $payload
 * @return array<string, mixed>
 */
function patcherly_http_error_detail($payload): array {
    if (!is_array($payload)) {
        return [];
    }
    $detail = $payload['detail'] ?? null;
    if (is_array($detail)) {
        return $detail;
    }
    return $payload;
}

/**
 * @param mixed $payload
 */
function patcherly_http_error_code($payload): ?string {
    $detail = patcherly_http_error_detail($payload);
    $code = $detail['code'] ?? null;
    if ($code === null || $code === '') {
        return null;
    }
    return (string) $code;
}

function patcherly_is_fix_approve_status(?string $status): bool {
    return $status !== null && in_array($status, PATCHERLY_FIX_APPROVE_STATUSES, true);
}

function patcherly_is_approve_409_soft_stop(?string $code): bool {
    return $code !== null && in_array($code, PATCHERLY_APPROVE_409_SOFT_STOP_CODES, true);
}
