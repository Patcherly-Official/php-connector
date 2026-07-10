<?php
/**
 * Read bounded sanitized file excerpts at ingest time (library-only, no HTTP).
 */
declare(strict_types=1);

require_once __DIR__ . '/../sanitizer.php';

if (!function_exists('patcherly_shared_file_context_allowed_roots')) {
    /** @return list<string> */
    function patcherly_shared_file_context_allowed_roots(): array {
        $roots = [];
        $cwd = getcwd();
        if (is_string($cwd) && $cwd !== '') {
            $real = realpath($cwd);
            if ($real !== false) {
                $roots[] = $real;
            }
        }
        $env = getenv('PATCHERLY_TARGET_ROOTS') ?: '';
        if ($env !== '') {
            foreach (explode(PATH_SEPARATOR, $env) as $part) {
                $part = trim($part);
                if ($part === '') {
                    continue;
                }
                $real = realpath($part);
                if ($real !== false) {
                    $roots[] = $real;
                }
            }
        }
        return array_values(array_unique($roots));
    }
}

if (!function_exists('patcherly_shared_path_is_within')) {
    function patcherly_shared_path_is_within(string $candidate, string $root): bool {
        if ($candidate === '' || $root === '') {
            return false;
        }
        $rootReal = realpath($root);
        if ($rootReal === false) {
            return false;
        }
        $rootWithSep = rtrim($rootReal, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        return $candidate === $rootReal || strpos($candidate, $rootWithSep) === 0;
    }
}

if (!function_exists('patcherly_shared_file_context_path_allowed')) {
    function patcherly_shared_file_context_path_allowed(string $realPath): bool {
        foreach (patcherly_shared_file_context_allowed_roots() as $root) {
            if (patcherly_shared_path_is_within($realPath, $root)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('patcherly_shared_extract_line_number')) {
    function patcherly_shared_extract_line_number(string $errorContext): ?int {
        $patterns = [
            '/on line\s+(\d+)/i',
            '/:(\d+)(?::\d+)?\s/',
            '/\((\d+)\)\s*$/',
            '/, line (\d+)/i',
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $errorContext, $matches) && isset($matches[1])) {
                return (int) $matches[1];
            }
        }
        return null;
    }
}

if (!function_exists('patcherly_shared_extract_file_path_from_log')) {
    function patcherly_shared_extract_file_path_from_log(string $errorContext): ?string {
        if ($errorContext === '') {
            return null;
        }
        if (preg_match('/File\s+["\']([^"\']+)["\']/', $errorContext, $matches)) {
            return $matches[1];
        }
        if (preg_match('/\bin\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s:]+?\.\w+)(?::\d+|\s+on line\s+\d+)/i', $errorContext, $matches)) {
            return $matches[1];
        }
        if (preg_match('/#\d+\s+((?:\/|[A-Za-z]:[\\\\\/])[^\s(]+?\.\w+)\(\d+\)/', $errorContext, $matches)) {
            return $matches[1];
        }
        if (preg_match('/\(((?:file:\/\/)?(?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):\d+(?::\d+)?\)/', $errorContext, $matches)) {
            return $matches[1];
        }
        if (preg_match('/\bat\s+(?:file:\/\/)?((?:\/|[A-Za-z]:[\\\\\/])[^\s()]+?\.\w+):\d+(?::\d+)?/', $errorContext, $matches)) {
            return $matches[1];
        }
        if (preg_match('/@((?:\/|[A-Za-z]:[\\\\\/])[^\s:@]+?\.\w+):\d+(?::\d+)?/', $errorContext, $matches)) {
            return $matches[1];
        }
        return null;
    }
}

if (!function_exists('patcherly_shared_read_file_context_excerpt')) {
    /** @return array<string,mixed>|null */
    function patcherly_shared_read_file_context_excerpt(
        string $filePath,
        ?int $lineNumber = null,
        int $contextLines = 50
    ): ?array {
        $filePath = trim($filePath);
        if ($filePath === '') {
            return null;
        }
        $contextLines = max(1, min(500, $contextLines));
        $realPath = realpath($filePath);
        if ($realPath === false || !is_file($realPath)) {
            return null;
        }
        if (!patcherly_shared_file_context_path_allowed($realPath)) {
            return null;
        }
        $fileContents = @file_get_contents($realPath);
        if ($fileContents === false) {
            return null;
        }
        $lines = explode("\n", $fileContents);
        $totalLines = count($lines);
        $startLine = 1;
        $endLine = $totalLines;
        if ($lineNumber !== null && $lineNumber > 0) {
            $startLine = max(1, $lineNumber - $contextLines);
            $endLine = min($totalLines, $lineNumber + $contextLines);
        }
        $extractedLines = array_slice($lines, $startLine - 1, $endLine - $startLine + 1);
        $content = implode("\n", $extractedLines);
        $result = \Patcherly\Connector\Sanitizer::sanitizeSensitiveData($content);
        return [
            'content' => $result['sanitized_content'],
            'redacted_ranges' => $result['redacted_lines'],
            'start_line' => $startLine,
            'end_line' => $endLine,
            'total_lines' => $totalLines,
            'file_path' => $filePath,
            'line_number' => $lineNumber,
        ];
    }
}

if (!function_exists('patcherly_shared_build_ingest_file_context')) {
    /** @return array<string,mixed>|null */
    function patcherly_shared_build_ingest_file_context(
        string $logLine,
        string $captureSource = 'log_monitor',
        ?string $filePath = null,
        ?int $lineNumber = null,
        int $contextLines = 50
    ): ?array {
        if ($filePath === null || $filePath === '') {
            $filePath = patcherly_shared_extract_file_path_from_log($logLine);
        }
        if (!$filePath) {
            return null;
        }
        if ($lineNumber === null) {
            $lineNumber = patcherly_shared_extract_line_number($logLine);
        }
        $excerpt = patcherly_shared_read_file_context_excerpt($filePath, $lineNumber, $contextLines);
        if ($excerpt === null) {
            return null;
        }
        $excerpt['capture_source'] = $captureSource;
        return $excerpt;
    }
}

if (!function_exists('patcherly_shared_enrich_ingest_payload_with_file_context')) {
    /** @param array<string,mixed> $payload */
    function patcherly_shared_enrich_ingest_payload_with_file_context(
        array $payload,
        string $logLine,
        string $captureSource = 'log_monitor',
        ?string $filePath = null,
        ?int $lineNumber = null
    ): array {
        $ctx = patcherly_shared_build_ingest_file_context(
            $logLine,
            $captureSource,
            $filePath,
            $lineNumber
        );
        if ($ctx !== null) {
            $payload['ingest_file_context'] = $ctx;
        }
        return $payload;
    }
}
