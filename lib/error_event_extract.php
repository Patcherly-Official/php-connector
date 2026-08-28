<?php
/**
 * Multi-line log error event extraction with incomplete-block carry.
 * Mirrors connectors/python/lib/error_event_extract.py
 */

declare(strict_types=1);

const PATCHERLY_INCOMPLETE_HOLD_SECONDS = 2.0;
const PATCHERLY_MAX_PENDING_LINES = 500;

/**
 * @param string[] $lines
 */
function patcherly_python_traceback_closed(array $lines): bool {
    $sawTb = false;
    foreach ($lines as $line) {
        $stripped = trim((string) $line);
        if ($stripped === '') {
            continue;
        }
        if (preg_match('/^\s*Traceback\b/i', $stripped) === 1) {
            $sawTb = true;
            continue;
        }
        if ($sawTb && preg_match('/^\w+(?:Error|Exception):/i', $stripped) === 1) {
            return true;
        }
    }
    return false;
}

/**
 * @param string[] $lines
 */
function patcherly_orphan_file_stack_closed(array $lines): bool {
    $sawFile = false;
    foreach ($lines as $line) {
        $stripped = trim((string) $line);
        if ($stripped === '') {
            continue;
        }
        if (preg_match('/^\s*File\s+["\']/', (string) $line) === 1) {
            $sawFile = true;
            continue;
        }
        if ($sawFile && preg_match('/^\w+(?:Error|Exception):/i', $stripped) === 1) {
            return true;
        }
    }
    return false;
}

/**
 * PHP stacks are closed by "#N {main}" and/or a "thrown in path:line" trailer.
 * Bare "#N" frames without those markers are incomplete (more frames may follow).
 *
 * @param string[] $lines
 */
function patcherly_php_stack_closed(array $lines): bool {
    foreach ($lines as $line) {
        $stripped = trim((string) $line);
        if ($stripped === '') {
            continue;
        }
        if (preg_match('/^\s*thrown\s+in\s+/i', $stripped) === 1) {
            return true;
        }
        if (
            preg_match('/^\s*#\d+\s+/', $stripped) === 1
            && preg_match('/\{main\}/', $stripped) === 1
        ) {
            return true;
        }
    }
    return false;
}

/**
 * @param string[] $lines
 */
function patcherly_looks_incomplete_error_block(array $lines): bool {
    if ($lines === []) {
        return false;
    }
    $nonempty = [];
    foreach ($lines as $line) {
        $s = rtrim((string) $line, "\r\n");
        if (trim($s) !== '') {
            $nonempty[] = $s;
        }
    }
    if ($nonempty === []) {
        return false;
    }

    $hasTraceback = false;
    $hasFile = false;
    $hasPhpStack = false;
    $hasNodeAt = false;
    foreach ($nonempty as $ln) {
        if (preg_match('/^\s*Traceback\b/i', $ln) === 1) {
            $hasTraceback = true;
        }
        if (
            preg_match('/^\s*Stack trace\s*:/i', $ln) === 1
            || preg_match('/^\s*#\d+\s+/', $ln) === 1
        ) {
            $hasPhpStack = true;
        }
    }
    foreach ($lines as $line) {
        if (preg_match('/^\s*File\s+["\']/', (string) $line) === 1) {
            $hasFile = true;
        }
        if (preg_match('/^\s+at\s+/', (string) $line) === 1) {
            $hasNodeAt = true;
        }
    }

    if ($hasTraceback) {
        return !patcherly_python_traceback_closed($lines);
    }
    if ($hasFile && !$hasTraceback) {
        return !patcherly_orphan_file_stack_closed($lines);
    }
    // WP debug.log often emits ERROR + bare #N frames (no "Stack trace:" label).
    if ($hasPhpStack) {
        return !patcherly_php_stack_closed($lines);
    }

    $last = trim($nonempty[count($nonempty) - 1]);
    if (
        preg_match('/\bERROR\b.*\b\w+(?:Error|Exception)\s*:/i', $last) === 1
        && !$hasTraceback
        && !$hasFile
    ) {
        return true;
    }
    if (
        preg_match('/\bERROR\b/i', $last) === 1
        && preg_match('/\bError\s*:/', $last) === 1
        && !$hasNodeAt
        && count($nonempty) <= 2
    ) {
        return true;
    }
    return false;
}

/**
 * @param string[] $lines
 * @return array{0: string[], 1: string[]} [events, leftover]
 */
function patcherly_extract_error_events(array $lines, bool $holdIncomplete = true): array {
    $events = [];
    $current = [];
    // Stack frames / "Stack trace:" / Node "at" are continuation-only — never
    // start a new event alone (that created orphan stack-only incidents next to
    // "work/N failed:" companion lines that lack \berror\b).
    $startOrCont = '/^(Traceback\s|File\s+["\']|Exception:|Error:\s|PHP\s+(?:Fatal|Parse|Warning|Notice|Deprecated))/i';
    $errorWord = '/\b(error|exception|traceback|fatal|failed|failure)\b/i';
    $pythonExceptionLine = '/^\w+(?:Error|Exception):/i';

    $flush = static function () use (&$current, &$events): void {
        if (count($current) > 0) {
            $events[] = implode('', $current);
            $current = [];
        }
    };

    foreach ($lines as $raw) {
        $line = (string) $raw;
        if ($line !== '' && substr($line, -1) !== "\n") {
            $line .= "\n";
        }
        $stripped = trim($line);
        // PHP fatals emit "Stack trace:" then #N frames then "thrown in path:line".
        // Those must stay on the same event as the PHP Fatal header — otherwise
        // log-monitor ingest creates header-only + stack-only duplicates.
        $isContinuation = count($current) > 0 && (
            str_starts_with($line, ' ')
            || str_starts_with($line, "\t")
            || preg_match('/^\s+at\s+/', $line) === 1
            || ($stripped !== '' && $stripped[0] === '#')
            || preg_match('/^\s*Stack\s+trace\s*:/i', $stripped) === 1
            || preg_match('/^\s*thrown\s+in\s+/i', $stripped) === 1
            || preg_match($pythonExceptionLine, $stripped) === 1
            || preg_match('/^[\s^~]+$/', rtrim($line, "\r\n")) === 1
            || ($stripped !== '' && preg_match('/^[\^~]+$/', $stripped) === 1)
            || str_starts_with($stripped, 'raise ')
        );
        if (preg_match($startOrCont, $line) === 1 || $isContinuation) {
            $current[] = $line;
        } elseif ($stripped !== '' && preg_match($errorWord, $stripped) === 1) {
            $flush();
            $current[] = $line;
        } elseif (count($current) > 0 && $stripped === '') {
            $flush();
        } elseif (count($current) > 0) {
            $flush();
        }
    }

    $leftover = [];
    if (count($current) > 0) {
        if ($holdIncomplete && patcherly_looks_incomplete_error_block($current)) {
            $leftover = $current;
            $current = [];
        } else {
            $flush();
        }
    }

    if (count($events) === 0 && count($leftover) === 0) {
        $errorLines = array_values(array_filter($lines, static function ($l) {
            return preg_match('/\b(error|exception|traceback|fatal|critical|failed|failure|rejection)\b/i', (string) $l) === 1
                || preg_match('/^\s*\w+(Error|Exception):/i', (string) $l) === 1;
        }));
        if (count($errorLines) > 0) {
            $joined = '';
            foreach ($errorLines as $el) {
                $el = (string) $el;
                $joined .= (substr($el, -1) === "\n") ? $el : ($el . "\n");
            }
            $events[] = $joined;
        }
    }

    return [$events, $leftover];
}

/**
 * @param array{pending?: string[], since?: float|null} $state
 * @param string[] $newLines
 * @return array{0: string[], 1: array{pending: string[], since: float|null}}
 */
function patcherly_ingest_log_lines_with_carry(
    array $state,
    array $newLines,
    ?float $now = null,
    float $holdSeconds = PATCHERLY_INCOMPLETE_HOLD_SECONDS,
    int $maxPendingLines = PATCHERLY_MAX_PENDING_LINES
): array {
    $now = $now ?? microtime(true);
    $pending = $state['pending'] ?? [];
    $since = $state['since'] ?? null;
    $combined = array_merge($pending, $newLines);
    if ($combined === []) {
        return [[], ['pending' => [], 'since' => null]];
    }

    $force = false;
    if ($since !== null && ($now - (float) $since) >= $holdSeconds) {
        $force = true;
    }
    if (count($combined) >= $maxPendingLines) {
        $force = true;
    }

    [$events, $leftover] = patcherly_extract_error_events($combined, !$force);
    if ($leftover !== []) {
        $newState = [
            'pending' => $leftover,
            'since' => $since ?? $now,
        ];
    } else {
        $newState = ['pending' => [], 'since' => null];
    }
    return [$events, $newState];
}

/**
 * Apply incomplete-block hold to a raw log chunk and compute the next byte offset.
 *
 * Used by the WordPress main plugin and Rescue MU-plugin (each request is a new
 * process, so incomplete tails rewind the persisted byte offset).
 *
 * @return array{events: string[], offset: int, carry_since: float|null}
 */
function patcherly_partition_log_chunk(
    string $chunk,
    int $byte_offset,
    int $file_size,
    ?float $carry_since = null,
    ?float $now = null,
    float $hold_seconds = PATCHERLY_INCOMPLETE_HOLD_SECONDS
): array {
    $now = $now ?? microtime(true);
    $chunk_end = $byte_offset + strlen($chunk);
    $at_eof = $chunk_end >= $file_size;

    $lines = preg_split('/\r\n|\r|\n/', $chunk);
    if (!is_array($lines)) {
        $lines = [];
    }
    $expanded = [];
    foreach ($lines as $line) {
        if (!is_string($line)) {
            continue;
        }
        if (function_exists('patcherly_split_log_occurrences') && trim($line) !== '') {
            foreach (patcherly_split_log_occurrences($line) as $occurrence) {
                $expanded[] = $occurrence;
            }
        } elseif (trim($line) !== '') {
            $expanded[] = $line;
        }
    }

    [$events, $leftover] = patcherly_extract_error_events($expanded, true);
    if ($leftover === []) {
        return [
            'events' => $events,
            'offset' => $chunk_end,
            'carry_since' => null,
        ];
    }

    $hold_lines = array_map(static function ($ln) {
        return rtrim((string) $ln, "\r\n");
    }, $leftover);
    $hold_text = implode("\n", $hold_lines);
    // Default: do not advance past this chunk if we cannot locate leftover.
    $new_offset = $byte_offset;
    $pos = ($hold_text !== '') ? strrpos($chunk, $hold_text) : false;
    if ($pos !== false) {
        $new_offset = $byte_offset + $pos;
    }

    if ($at_eof) {
        $since = $carry_since ?? $now;
        if (($now - (float) $since) >= $hold_seconds) {
            $forced = implode("\n", $hold_lines);
            if (trim($forced) !== '') {
                $events[] = $forced;
            }
            return [
                'events' => $events,
                'offset' => $chunk_end,
                'carry_since' => null,
            ];
        }
        return [
            'events' => $events,
            'offset' => $new_offset,
            'carry_since' => $since,
        ];
    }

    return [
        'events' => $events,
        'offset' => $new_offset,
        'carry_since' => null,
    ];
}
