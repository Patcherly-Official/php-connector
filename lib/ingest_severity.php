<?php
/** AUTO-GENERATED from config/settings_schema.yaml + log_ingest_skip_patterns.yaml — do not edit by hand. */
declare(strict_types=1);

if (!function_exists('patcherly_shared_should_skip_log_line_for_ingest')) {
    function patcherly_shared_should_skip_log_line_for_ingest(string $log_line): bool {
        $line = trim($log_line);
        if ($line === '') {
            return true;
        }
        $keep = [
            "PHP\\s+Fatal",
            "PHP\\s+Parse\\s+error",
            "PHP\\s+Recoverable\\s+fatal",
            "^Fatal error:",
            "Maximum execution time|Allowed memory size",
            "Uncaught\\s+\\S*(Error|Exception)",
            "^Traceback\\s",
            "^\\w+(Error|Exception):",
            "^Exception:",
            "^Error:\\s",
            "Unhandled\\s+(Promise\\s+)?Rejection",
            "uncaughtException|uncaught exception",
            "Assertion failed",
            "File\\s+[\"']",
            "^\\s*#\\d+\\s+",
            "^\\s+at\\s+",
            "\"level\"\\s*:\\s*\"(error|fatal|critical)\"",
            "\"level\"\\s*:\\s*50\\b",
            "\"severity\"\\s*:\\s*\"(ERROR|CRITICAL|FATAL)\"",
        ];
        $skip = [
            "^\\(node:\\d+\\)\\s+\\[DEP\\d+\\]",
            "DeprecationWarning:",
            "^UserWarning:",
            "^\\[info\\]",
            "^INFO:",
            "^DEBUG:",
        ];
        $phpPrefix = "^PHP\\s+(Notice|Deprecated|Warning|Strict\\s+standards|Info)\\s*:";
        $subs = ["auditor:scan", "\"kind\":\"installed-plugin\""];
        $failureSignal = "\\b(error|exception|traceback|fatal|critical|panic|failed|failure|rejection|errno|segfault)\\b|^\\w+(Error|Exception):";
        foreach ($keep as $pattern) {
            if (@preg_match('/' . str_replace('/', '\/', $pattern) . '/i', $line) === 1) {
                return false;
            }
        }
        if ($phpPrefix !== '' && @preg_match('/' . str_replace('/', '\/', $phpPrefix) . '/i', $line) === 1) {
            return true;
        }
        foreach ($skip as $pattern) {
            if (@preg_match('/' . str_replace('/', '\/', $pattern) . '/i', $line) === 1) {
                return true;
            }
        }
        $lower = strtolower($line);
        foreach ($subs as $sub) {
            if ($sub !== '' && strpos($lower, strtolower((string) $sub)) !== false) {
                return true;
            }
        }
        if (@preg_match('/' . str_replace('/', '\/', $failureSignal) . '/i', $line) !== 1) {
            return true;
        }
        return false;
    }
}

if (!function_exists('patcherly_shared_default_error_type_severities')) {
    function patcherly_shared_default_error_type_severities(): array {
        return [
            "database"         => "High",
            "fatal"            => "High",
            "hook"             => "Medium",
            "import"           => "Low",
            "logic"            => "Medium",
            "notice"           => "Low",
            "null_reference"   => "Medium",
            "other"            => "High",
            "parse"            => "Medium",
            "reference"        => "Medium",
            "runtime"          => "Medium",
            "syntax"           => "Low",
            "type"             => "Medium",
            "typo"             => "Low",
            "warning"          => "Low",
        ];
    }
}

if (!function_exists('patcherly_shared_infer_error_type_from_log_line')) {
    function patcherly_shared_infer_error_type_from_log_line(string $log_line): string {
        $line = strtolower($log_line);
        if (strpos($line, 'parse error') !== false) {
            return 'parse';
        }
        if (strpos($line, 'fatal error') !== false) {
            return 'fatal';
        }
        if (strpos($line, 'database') !== false) {
            return 'database';
        }
        if (strpos($line, 'warning') !== false || strpos($line, 'deprecated') !== false) {
            return 'warning';
        }
        if (strpos($line, 'notice') !== false) {
            return 'notice';
        }
        if (strpos($line, 'uncaught') !== false || preg_match('/\berror\b/', $line) === 1) {
            return 'runtime';
        }
        return 'other';
    }
}

if (!function_exists('patcherly_shared_severity_for_error_type')) {
    function patcherly_shared_severity_for_error_type(string $error_type): string {
        $map = patcherly_shared_default_error_type_severities();
        $key = strtolower(trim($error_type));
        return $map[$key] ?? 'High';
    }
}

if (!function_exists('patcherly_shared_build_ingest_severity_fields')) {
    /** @return array{error_type: string, severity: string} */
    function patcherly_shared_build_ingest_severity_fields(string $log_line): array {
        $error_type = patcherly_shared_infer_error_type_from_log_line($log_line);
        return [
            'error_type' => $error_type,
            'severity'   => patcherly_shared_severity_for_error_type($error_type),
        ];
    }
}
