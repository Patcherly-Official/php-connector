<?php
/**
 * Patch Applicator for PHP Agent
 * Handles parsing and applying unified diff patches to files.
 */

class PatchParseError extends Exception {
}

class PatchApplyError extends Exception {
}

class FileLock {
    /**
     * File locking mechanism using lock files.
     */
    private $filePath;
    private $lockFile;
    private $lockHandle = null;
    
    public function __construct($filePath) {
        $this->filePath = $filePath;
        $this->lockFile = $filePath . '.lock';
    }
    
    public function acquire() {
        try {
            // Try to create lock file exclusively
            $this->lockHandle = fopen($this->lockFile, 'x');
            if ($this->lockHandle === false) {
                throw new PatchApplyError("File is locked: {$this->filePath}");
            }
            fwrite($this->lockHandle, getmypid() . "\n");
            fflush($this->lockHandle);
            return $this;
        } catch (Exception $e) {
            if (file_exists($this->lockFile)) {
                throw new PatchApplyError("File is locked: {$this->filePath}");
            }
            throw $e;
        }
    }
    
    public function release() {
        if ($this->lockHandle) {
            fclose($this->lockHandle);
            $this->lockHandle = null;
        }
        if (file_exists($this->lockFile)) {
            @unlink($this->lockFile);
        }
    }
}

class Hunk {
    /**
     * Represents a hunk (block of changes) in a patch.
     */
    public $origStart;
    public $origLen;
    public $newStart;
    public $newLen;
    public $context;
    public $removed;
    public $added;
    /** @var list<array{type:string,text:string}> Diff-body order (context/removed/added). */
    public $segments;
    
    /**
     * @param list<array{type:string,text:string}> $segments
     */
    public function __construct($origStart, $origLen, $newStart, $newLen, $context, $removed, $added, $segments = []) {
        $this->origStart = $origStart;
        $this->origLen = $origLen;
        $this->newStart = $newStart;
        $this->newLen = $newLen;
        $this->context = $context;
        $this->removed = $removed;
        $this->added = $added;
        $this->segments = $segments;
    }

    /** @return int Lines consumed from the original file for this hunk. */
    private function orig_lines_in_hunk(): int {
        if ($this->segments !== []) {
            return count($this->orig_file_segments());
        }
        return count($this->context) + count($this->removed);
    }

    /**
     * Segments that consume lines from the original file.
     * Trailing context after the added block is decorative in many AI diffs and must not
     * be validated against (or consume) lines past a truncated/corrupt target file.
     *
     * @return list<array{type:string,text:string}>
     */
    private function orig_file_segments(): array {
        if ($this->segments === []) {
            return [];
        }
        $result = [];
        $pastAdded = false;
        foreach ($this->segments as $seg) {
            $type = $seg['type'] ?? '';
            if ($type === 'added') {
                $pastAdded = true;
                continue;
            }
            if ($pastAdded && $type === 'context') {
                continue;
            }
            $result[] = $seg;
        }
        return $result;
    }
    
    public function canApplyTo($fileLines) {
        /**
         * Check if this hunk can be applied to the file.
         * Returns: ['canApply' => bool, 'error' => string|null]
         */
        if ($this->origStart < 1) {
            return ['canApply' => false, 'error' => 'Invalid start line (must be >= 1)'];
        }

        $origLines = $this->orig_lines_in_hunk();
        if ($this->origStart - 1 + $origLines > count($fileLines)) {
            return [
                'canApply' => false,
                'error' => "Hunk starts at line {$this->origStart} but file has only " . count($fileLines) . " lines"
            ];
        }

        if ($this->segments !== []) {
            $idx = $this->origStart - 1;
            foreach ($this->orig_file_segments() as $seg) {
                if ($idx >= count($fileLines)) {
                    return ['canApply' => false, 'error' => 'Context mismatch: file too short'];
                }
                $expected = rtrim((string) ($seg['text'] ?? ''), "\r\n");
                $actual = rtrim($fileLines[$idx], "\r\n");
                if ($actual !== $expected) {
                    return [
                        'canApply' => false,
                        'error' => "Context mismatch at line " . ($idx + 1)
                    ];
                }
                $idx++;
            }
            return ['canApply' => true, 'error' => null];
        }
        
        $startIdx = $this->origStart - 1;
        foreach ($this->context as $i => $expectedLine) {
            if ($startIdx + $i >= count($fileLines)) {
                return ['canApply' => false, 'error' => 'Context mismatch: file too short'];
            }
            $expected = rtrim($expectedLine, "\r\n");
            $actual = rtrim($fileLines[$startIdx + $i], "\r\n");
            if ($actual !== $expected) {
                return [
                    'canApply' => false,
                    'error' => "Context mismatch at line " . ($this->origStart + $i)
                ];
            }
        }
        
        return ['canApply' => true, 'error' => null];
    }

    public function matchesPostImage($fileLines) {
        if ($this->newStart < 1) {
            return ['matches' => false, 'error' => 'Invalid new start line (must be >= 1)'];
        }

        $idx = $this->newStart - 1;
        if ($this->segments !== []) {
            foreach ($this->segments as $seg) {
                $type = $seg['type'] ?? '';
                if ($type === 'removed') {
                    continue;
                }
                if ($idx >= count($fileLines)) {
                    return ['matches' => false, 'error' => 'Post-image mismatch: file too short'];
                }
                $expected = rtrim((string) ($seg['text'] ?? ''), "\r\n");
                $actual = rtrim($fileLines[$idx], "\r\n");
                if ($actual !== $expected) {
                    return [
                        'matches' => false,
                        'error' => "Post-image mismatch at line " . ($idx + 1),
                    ];
                }
                $idx++;
            }
            return ['matches' => true, 'error' => null];
        }

        foreach ($this->context as $line) {
            if ($idx >= count($fileLines)) {
                return ['matches' => false, 'error' => 'Post-image mismatch: file too short'];
            }
            $expected = rtrim($line, "\r\n");
            $actual = rtrim($fileLines[$idx], "\r\n");
            if ($actual !== $expected) {
                return [
                    'matches' => false,
                    'error' => "Post-image mismatch at line " . ($idx + 1),
                ];
            }
            $idx++;
        }
        foreach ($this->added as $line) {
            if ($idx >= count($fileLines)) {
                return ['matches' => false, 'error' => 'Post-image mismatch: file too short'];
            }
            $expected = rtrim($line, "\r\n");
            $actual = rtrim($fileLines[$idx], "\r\n");
            if ($actual !== $expected) {
                return [
                    'matches' => false,
                    'error' => "Post-image mismatch at line " . ($idx + 1),
                ];
            }
            $idx++;
        }

        return ['matches' => true, 'error' => null];
    }

    /**
     * Re-anchor hunk line numbers by searching for the removed line + leading context.
     * Handles ingest_snapshot line drift when the live file gained or lost lines above the edit.
     */
    public function tryRelocateInFile($fileLines): bool {
        if ($this->canApplyTo($fileLines)['canApply']) {
            return true;
        }
        if ($this->segments === [] || $this->removed === []) {
            return false;
        }

        $leadingContext = [];
        foreach ($this->segments as $seg) {
            $type = $seg['type'] ?? '';
            if ($type === 'removed') {
                break;
            }
            if ($type === 'context') {
                $leadingContext[] = rtrim((string) ($seg['text'] ?? ''), "\r\n");
            }
        }

        $removedNeedle = rtrim((string) ($this->removed[0] ?? ''), "\r\n");
        if ($removedNeedle === '') {
            return false;
        }

        $ctxCount = count($leadingContext);
        $headerDelta = $this->newStart - $this->origStart;

        for ($i = 0; $i < count($fileLines); $i++) {
            if (rtrim($fileLines[$i], "\r\n") !== $removedNeedle) {
                continue;
            }
            $ctxStart = $i - $ctxCount;
            if ($ctxStart < 0) {
                continue;
            }
            $matched = true;
            for ($j = 0; $j < $ctxCount; $j++) {
                if (rtrim($fileLines[$ctxStart + $j], "\r\n") !== $leadingContext[$j]) {
                    $matched = false;
                    break;
                }
            }
            if (!$matched) {
                continue;
            }
            $this->origStart = $ctxStart + 1;
            $this->newStart = $this->origStart + $headerDelta;
            return $this->canApplyTo($fileLines)['canApply'];
        }

        return false;
    }
}

class FilePatch {
    /**
     * Represents a patch for a single file.
     */
    public $filePath;
    public $hunks = [];
    
    public function __construct($filePath) {
        $this->filePath = $filePath;
    }
    
    public function addHunk($hunk) {
        $this->hunks[] = $hunk;
    }
    
    public function canApplyTo($filePath) {
        /**
         * Check if this patch can be applied to the file.
         * Returns: ['canApply' => bool, 'error' => string|null]
         */
        if (!file_exists($filePath)) {
            // If file doesn't exist, check if all hunks are additions
            foreach ($this->hunks as $hunk) {
                if ($hunk->origLen > 0) {
                    return ['canApply' => false, 'error' => 'File does not exist and patch contains deletions'];
                }
            }
            return ['canApply' => true, 'error' => null];
        }
        
        // Read file
        $fileLines = [];
        try {
            $content = file_get_contents($filePath);
            if ($content === false) {
                return ['canApply' => false, 'error' => 'Cannot read file'];
            }
            $fileLines = explode("\n", $content);
            // Add newlines back (except last line if file doesn't end with newline)
            $fileLines = array_map(function($line, $idx, $arr) use ($content) {
                if ($idx < count($arr) - 1 || substr($content, -1) === "\n") {
                    return $line . "\n";
                }
                return $line;
            }, $fileLines, array_keys($fileLines), array_fill(0, count($fileLines), $fileLines));
        } catch (Exception $e) {
            return ['canApply' => false, 'error' => "Cannot read file: {$e->getMessage()}"];
        }
        
        // Check each hunk
        foreach ($this->hunks as $i => $hunk) {
            if (!$hunk->canApplyTo($fileLines)['canApply']) {
                $hunk->tryRelocateInFile($fileLines);
            }
            $result = $hunk->canApplyTo($fileLines);
            if (!$result['canApply']) {
                return ['canApply' => false, 'error' => "Hunk " . ($i + 1) . ": {$result['error']}"];
            }
        }
        
        return ['canApply' => true, 'error' => null];
    }

    public function matchesPostImage($filePath) {
        if (!file_exists($filePath)) {
            return ['matches' => false, 'error' => 'File does not exist'];
        }

        $fileLines = [];
        try {
            $content = file_get_contents($filePath);
            if ($content === false) {
                return ['matches' => false, 'error' => 'Cannot read file'];
            }
            $fileLines = explode("\n", $content);
            $fileLines = array_map(function($line, $idx, $arr) use ($content) {
                if ($idx < count($arr) - 1 || substr($content, -1) === "\n") {
                    return $line . "\n";
                }
                return $line;
            }, $fileLines, array_keys($fileLines), array_fill(0, count($fileLines), $fileLines));
        } catch (Exception $e) {
            return ['matches' => false, 'error' => "Cannot read file: {$e->getMessage()}"];
        }

        foreach ($this->hunks as $i => $hunk) {
            $result = $hunk->matchesPostImage($fileLines);
            if (!$result['matches']) {
                return ['matches' => false, 'error' => "Hunk " . ($i + 1) . ": {$result['error']}"];
            }
        }

        return ['matches' => true, 'error' => null];
    }
}

class PatchApplicator {
    /**
     * Parses and applies unified diff patches.
     */
    
    private $allowedTargetRoots = [];
    
    public function __construct() {
        echo "Initialized PatchApplicator\n";
        $configuredRoots = getenv('PATCHERLY_TARGET_ROOTS') ?: '';
        $roots = array_filter(array_map('trim', explode(PATH_SEPARATOR, $configuredRoots)));
        $roots[] = getcwd();
        $normalized = [];
        foreach ($roots as $root) {
            $resolved = realpath($root) ?: $root;
            if ($resolved && !in_array($resolved, $normalized, true)) {
                $normalized[] = $resolved;
            }
        }
        $this->allowedTargetRoots = $normalized;
    }

    /**
     * Canonical absolute path for prefix checks when the leaf file may not exist yet.
     */
    private function normalizePathForAllowedRootCheck($candidatePath): ?string {
        $candidatePath = (string) $candidatePath;
        $resolved = realpath($candidatePath);
        if ($resolved !== false) {
            return $resolved;
        }
        $base = basename($candidatePath);
        if ($base === '' || $base === '.' || $base === '..') {
            return null;
        }
        $dir = dirname($candidatePath);
        $resolvedDir = realpath($dir);
        if ($resolvedDir === false) {
            return null;
        }
        return $resolvedDir . DIRECTORY_SEPARATOR . $base;
    }

    private function isPathWithinAllowedRoots($candidatePath) {
        $resolved = $this->normalizePathForAllowedRootCheck($candidatePath);
        if ($resolved === null) {
            return false;
        }
        foreach ($this->allowedTargetRoots as $root) {
            if ($resolved === $root) {
                return true;
            }
            $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (strpos($resolved, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    public function parsePatch($patchText) {
        /**
         * Parse unified diff format into FilePatch objects.
         * Throws PatchParseError if patch cannot be parsed.
         */
        $filePatches = [];
        $lines = explode("\n", $patchText);
        
        $i = 0;
        while ($i < count($lines)) {
            // Look for file header: --- a/path
            if (strpos($lines[$i], '---') === 0) {
                if (preg_match('/^---\s+a\/(.+)$/', $lines[$i], $matches) ||
                    preg_match('/^---\s+(.+)$/', $lines[$i], $matches)) {
                    $filePath = trim($matches[1]);
                    
                    // Skip to +++ line
                    $i++;
                    if ($i >= count($lines) || strpos($lines[$i], '+++') !== 0) {
                        throw new PatchParseError("Missing +++ line after --- for {$filePath}");
                    }
                    
                    // Create FilePatch
                    $filePatch = new FilePatch($filePath);
                    
                    // Parse hunks
                    $i++;
                    while ($i < count($lines)) {
                        $line = $lines[$i];
                        
                        // Empty line between hunks
                        if (!trim($line)) {
                            $i++;
                            continue;
                        }
                        
                        // New file header - done with this file
                        if (strpos($line, '---') === 0) {
                            break;
                        }
                        
                        // Hunk header: @@ -orig_start,orig_len +new_start,new_len @@
                        if (strpos($line, '@@') === 0) {
                            list($hunk, $i) = $this->parseHunk($lines, $i);
                            $filePatch->addHunk($hunk);
                            continue;
                        }
                        
                        $i++;
                    }
                    
                    $filePatches[] = $filePatch;
                } else {
                    $i++;
                }
            } else {
                $i++;
            }
        }
        
        if (empty($filePatches)) {
            throw new PatchParseError('No file patches found in patch text');
        }
        
        return $filePatches;
    }
    
    private function parseHunk($lines, $startIdx) {
        /**
         * Parse a hunk from patch lines.
         */
        $hunkHeader = rtrim($lines[$startIdx], "\r\n");
        
        // Parse hunk header: @@ -orig_start,orig_len +new_start,new_len @@ [optional section]
        // Optional trailing text after the second @@ is valid unified-diff (git style).
        if (!preg_match('/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/', $hunkHeader, $matches)) {
            throw new PatchParseError("Invalid hunk header: {$hunkHeader}");
        }
        
        $origStart = intval($matches[1]);
        $origLen = intval($matches[2] ?? 1);
        $newStart = intval($matches[3]);
        $newLen = intval($matches[4] ?? 1);
        
        $context = [];
        $removed = [];
        $added = [];
        $segments = [];
        
        // Parse hunk content
        $i = $startIdx + 1;
        while ($i < count($lines)) {
            $line = $lines[$i];
            
            // End of hunk
            if (strpos($line, '@@') === 0 || strpos($line, '---') === 0) {
                break;
            }
            
            if (strpos($line, ' ') === 0) {
                $text = substr($line, 1);
                $context[] = $text;
                $segments[] = ['type' => 'context', 'text' => $text];
            } elseif (strpos($line, '-') === 0) {
                $text = substr($line, 1);
                $removed[] = $text;
                $segments[] = ['type' => 'removed', 'text' => $text];
            } elseif (strpos($line, '+') === 0) {
                $text = substr($line, 1);
                $added[] = $text;
                $segments[] = ['type' => 'added', 'text' => $text];
            } elseif (trim($line) === '') {
                $context[] = '';
                $segments[] = ['type' => 'context', 'text' => ''];
            }
            
            $i++;
        }
        
        return [new Hunk($origStart, $origLen, $newStart, $newLen, $context, $removed, $added, $segments), $i];
    }
    
    public function applyPatch($filePatch, $filePath, $dryRun = false, $verifySyntax = true) {
        /**
         * Apply a patch to a file.
         * Returns: ['success' => bool, 'message' => string, 'syntaxErrors' => array|null]
         */
        if (!$this->isPathWithinAllowedRoots($filePath)) {
            return [
                'success' => false,
                'message' => "File path is outside allowed target roots: {$filePath}",
                'syntaxErrors' => null
            ];
        }
        // Check if patch can be applied
        $canApply = $filePatch->canApplyTo($filePath);
        if (!$canApply['canApply']) {
            $already = $filePatch->matchesPostImage($filePath);
            if (!empty($already['matches'])) {
                return [
                    'success' => true,
                    'message' => "Patch already applied to {$filePath}",
                    'syntaxErrors' => null,
                ];
            }
            return [
                'success' => false,
                'message' => "Cannot apply patch: {$canApply['error']}",
                'syntaxErrors' => null
            ];
        }
        
        if ($dryRun) {
            return [
                'success' => true,
                'message' => "Dry-run: Patch would be applied successfully to {$filePath}",
                'syntaxErrors' => null
            ];
        }
        
        // Acquire file lock
        $lock = new FileLock($filePath);
        try {
            $lock->acquire();
            
            // Read original file
            $originalLines = [];
            if (file_exists($filePath)) {
                $content = file_get_contents($filePath);
                if ($content !== false) {
                    $originalLines = explode("\n", $content);
                    // Add newlines back
                    $originalLines = array_map(function($line, $idx, $arr) use ($content) {
                        if ($idx < count($arr) - 1 || substr($content, -1) === "\n") {
                            return $line . "\n";
                        }
                        return $line;
                    }, $originalLines, array_keys($originalLines), array_fill(0, count($originalLines), $originalLines));
                }
            }
            
            // Apply hunks (in reverse order to maintain line numbers)
            $modifiedLines = $originalLines;
            
            // Sort hunks by start line in reverse order
            usort($filePatch->hunks, function($a, $b) {
                return $b->origStart - $a->origStart;
            });
            
            foreach ($filePatch->hunks as $hunk) {
                $modifiedLines = $this->applyHunk($hunk, $modifiedLines);
            }
            
            // Write modified file
            $content = implode('', $modifiedLines);
            file_put_contents($filePath, $content);
            
            // Verify syntax if requested
            $syntaxErrors = null;
            if ($verifySyntax) {
                $syntaxOk = $this->verifySyntax($filePath);
                if (!$syntaxOk['valid']) {
                    // Restore original file
                    file_put_contents($filePath, implode('', $originalLines));
                    $lock->release();
                    return [
                        'success' => false,
                        'message' => 'Syntax validation failed',
                        'syntaxErrors' => $syntaxOk['errors']
                    ];
                }
                $syntaxErrors = $syntaxOk['errors'] ?? [];
            }
            
            $lock->release();
            
            return [
                'success' => true,
                'message' => "Patch applied successfully to {$filePath}",
                'syntaxErrors' => $syntaxErrors
            ];
        } catch (PatchApplyError $e) {
            $lock->release();
            return [
                'success' => false,
                'message' => $e->getMessage(),
                'syntaxErrors' => null
            ];
        } catch (Exception $e) {
            $lock->release();
            echo "Error applying patch: {$e->getMessage()}\n";
            return [
                'success' => false,
                'message' => "Error applying patch: {$e->getMessage()}",
                'syntaxErrors' => null
            ];
        }
    }
    
    private function applyHunk($hunk, $fileLines) {
        /**
         * Apply a single hunk to file lines.
         */
        $startIdx = $hunk->origStart - 1;

        if (!empty($hunk->segments)) {
            $result = array_slice($fileLines, 0, $startIdx);
            $origConsumed = 0;
            $pastAdded = false;
            $trailingDecorative = [];
            foreach ($hunk->segments as $seg) {
                $type = $seg['type'] ?? '';
                $text = (string) ($seg['text'] ?? '');
                if ($type === 'context') {
                    if ($pastAdded) {
                        $trailingDecorative[] = $text;
                        continue;
                    }
                    $result[] = (substr($text, -1) === "\n") ? $text : ($text . "\n");
                    $origConsumed++;
                } elseif ($type === 'removed') {
                    $origConsumed++;
                } elseif ($type === 'added') {
                    $pastAdded = true;
                    $result[] = (substr($text, -1) === "\n") ? $text : ($text . "\n");
                }
            }
            $remainingStart = $startIdx + $origConsumed;
            if ($remainingStart < count($fileLines)) {
                $result = array_merge($result, array_slice($fileLines, $remainingStart));
            } elseif ($trailingDecorative !== []) {
                foreach ($trailingDecorative as $text) {
                    $result[] = (substr($text, -1) === "\n") ? $text : ($text . "\n");
                }
            }
            return $result;
        }
        
        // Remove old lines
        $linesToRemove = count($hunk->context) + count($hunk->removed);
        $result = array_slice($fileLines, 0, $startIdx);
        
        // Add context + new lines
        foreach ($hunk->context as $line) {
            $result[] = (substr($line, -1) === "\n") ? $line : ($line . "\n");
        }
        
        foreach ($hunk->added as $line) {
            $result[] = (substr($line, -1) === "\n") ? $line : ($line . "\n");
        }
        
        // Add remaining lines
        $remainingStart = $startIdx + $linesToRemove;
        if ($remainingStart < count($fileLines)) {
            $result = array_merge($result, array_slice($fileLines, $remainingStart));
        }
        
        return $result;
    }
    
    private function verifySyntax($filePath) {
        /**
         * Verify syntax of a PHP file.
         * Returns: ['valid' => bool, 'errors' => array]
         */
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        
        if ($ext !== 'php' && $ext !== 'phtml') {
            // For non-PHP files, assume valid
            return ['valid' => true, 'errors' => []];
        }
        
        try {
            // Parse with TOKEN_PARSE to validate PHP syntax without spawning shell commands.
            $code = @file_get_contents($filePath);
            if ($code === false) {
                return [
                    'valid' => false,
                    'errors' => ['Could not read file for syntax validation']
                ];
            }
            token_get_all($code, TOKEN_PARSE);
            return ['valid' => true, 'errors' => []];
        } catch (ParseError $e) {
            return [
                'valid' => false,
                'errors' => ["Syntax parse error: {$e->getMessage()}"]
            ];
        } catch (Exception $e) {
            return [
                'valid' => false,
                'errors' => ["Syntax check error: {$e->getMessage()}"]
            ];
        }
    }
}

