<?php
/**
 * Queue Manager for PHP Agent
 * Handles robust queue operations with file locking, corruption handling, and retry logic.
 */

class QueueManager {
    private $queuePath;
    private $lockPath;
    private $dlqPath;
    private $allowedRoots = [];
    private const MAX_QUEUE_SIZE = 1000;
    private const MAX_RETRIES = 5;
    
    public function __construct($queuePath) {
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
        $this->allowedRoots = $normalized;
        $resolvedQueuePath = $this->normalizePathForAllowedRootCheck($queuePath);
        if ($resolvedQueuePath === null) {
            throw new RuntimeException("Queue path could not be resolved to a safe canonical path: {$queuePath}");
        }
        if (!$this->isPathWithinAllowedRoots($resolvedQueuePath)) {
            throw new RuntimeException("Queue path is outside allowed roots: {$resolvedQueuePath}");
        }
        $this->queuePath = $resolvedQueuePath;
        $this->lockPath = $resolvedQueuePath . '.lock';
        $this->dlqPath = str_replace('.jsonl', '.dlq.jsonl', $resolvedQueuePath);
    }

    /**
     * Canonical absolute path for prefix checks when the leaf file may not exist yet.
     * Rejects paths that cannot be anchored (e.g. unresolved dirname) so ".." cannot bypass checks.
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

    private function isPathWithinAllowedRoots($candidatePath): bool {
        $resolved = $this->normalizePathForAllowedRootCheck($candidatePath);
        if ($resolved === null) {
            return false;
        }
        foreach ($this->allowedRoots as $root) {
            if ($resolved === $root) return true;
            $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (strpos($resolved, $prefix) === 0) return true;
        }
        return false;
    }
    
    public function enqueue(array $payload) : void {
        if (empty($payload['idempotency_key'])) {
            $payload['idempotency_key'] = $this->uuidv4();
        }
        try {
            // Acquire lock
            $lockHandle = fopen($this->lockPath, 'c+');
            if (!$lockHandle || !flock($lockHandle, LOCK_EX | LOCK_NB)) {
                // Lock held, try to append without lock (fallback)
                if (file_put_contents($this->queuePath, json_encode($payload) . "\n", FILE_APPEND | LOCK_EX) === false) {
                    // Disk full?
                    $lastError = error_get_last();
                    if ($lastError && (strpos($lastError['message'] ?? '', 'disk') !== false || 
                        strpos($lastError['message'] ?? '', 'No space') !== false)) {
                        $this->moveToDLQ(json_encode($payload));
                    }
                }
                if ($lockHandle) fclose($lockHandle);
                return;
            }
            
            // Read existing queue
            $queueLines = [];
            if (file_exists($this->queuePath)) {
                try {
                    $content = file_get_contents($this->queuePath);
                    if ($content !== false) {
                        $queueLines = array_filter(array_map('trim', explode("\n", $content)));
                    }
                } catch (\Throwable $e) {
                    // Corruption recovery
                    echo "Queue file corruption detected, attempting recovery\n";
                    $content = @file_get_contents($this->queuePath);
                    if ($content !== false) {
                        foreach (explode("\n", $content) as $line) {
                            $line = trim($line);
                            if ($line) {
                                json_decode($line, true);
                                if (json_last_error() === JSON_ERROR_NONE) {
                                    $queueLines[] = $line;
                                }
                            }
                        }
                    }
                }
            }
            
            // Check queue size limit
            if (count($queueLines) >= self::MAX_QUEUE_SIZE) {
                // Evict oldest entries
                $evicted = array_slice($queueLines, 0, count($queueLines) - self::MAX_QUEUE_SIZE + 1);
                $queueLines = array_slice($queueLines, count($queueLines) - self::MAX_QUEUE_SIZE + 1);
                $this->moveToDLQ(implode("\n", $evicted) . "\n");
                echo "Queue full, moved " . count($evicted) . " entries to dead letter queue\n";
            }
            
            // Append new payload
            $queueLines[] = json_encode($payload);
            
            // Write queue back
            file_put_contents($this->queuePath, implode("\n", $queueLines) . "\n");
            
            // Release lock
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            
        } catch (\Throwable $e) {
            // Disk full or other error
            if (strpos($e->getMessage(), 'disk') !== false || strpos($e->getMessage(), 'No space') !== false) {
                echo "Disk full, moving to dead letter queue\n";
                $this->moveToDLQ(json_encode($payload));
            } else {
                echo "Failed writing queue file: {$e->getMessage()}\n";
            }
        }
    }

    public function drainQueue(callable $processItem) : void {
        if (!file_exists($this->queuePath)) {
            return;
        }
        
        // Acquire lock
        $lockHandle = fopen($this->lockPath, 'c+');
        if (!$lockHandle || !flock($lockHandle, LOCK_EX | LOCK_NB)) {
            echo "Queue lock held, skipping drain cycle\n";
            if ($lockHandle) fclose($lockHandle);
            return;
        }
        
        try {
            // Read queue
            $lines = [];
            try {
                $content = file_get_contents($this->queuePath);
                if ($content !== false) {
                    $lines = array_filter(array_map('trim', explode("\n", $content)));
                }
            } catch (\Throwable $e) {
                echo "Queue file corruption detected during drain\n";
                // Try to recover valid JSON lines
                $content = @file_get_contents($this->queuePath);
                if ($content !== false) {
                    foreach (explode("\n", $content) as $line) {
                        $line = trim($line);
                        if ($line) {
                            json_decode($line, true);
                            if (json_last_error() === JSON_ERROR_NONE) {
                                $lines[] = $line;
                            }
                        }
                    }
                }
            }
            
            if (empty($lines)) {
                flock($lockHandle, LOCK_UN);
                fclose($lockHandle);
                return;
            }
            
            $remaining = [];
            $retryLater = [];
            $now = time();
            
            foreach ($lines as $line) {
                try {
                    $payload = json_decode($line, true);
                    if (!is_array($payload)) continue;
                    
                    // Extract retry count
                    $retryCount = $payload['_retry_count'] ?? 0;
                    if ($retryCount >= self::MAX_RETRIES) {
                        // Move to dead letter queue
                        echo "Payload exceeded max retries, moving to dead letter queue\n";
                        $this->moveToDLQ($line);
                        continue;
                    }
                    
                    // Check if it's time to retry
                    $nextRetry = $payload['_next_retry_at'] ?? 0;
                    if ($nextRetry > $now) {
                        // Not time to retry yet
                        $remaining[] = $line;
                        continue;
                    }
                    
                    // Process item
                    $result = $processItem($payload);
                    
                    if ($result === true || $result === 'success') {
                        // Success, don't re-add
                        continue;
                    } elseif ($result === 'duplicate') {
                        // Duplicate, skip
                        continue;
                    } elseif ($result === 'server_error') {
                        // Server error, retry with backoff
                        $payload['_retry_count'] = $retryCount + 1;
                        $payload['_next_retry_at'] = $now + (2 ** $retryCount); // Exponential backoff
                        $retryLater[] = json_encode($payload);
                    } else {
                        // Client error, move to DLQ
                        echo "Client error, moving to dead letter queue\n";
                        $this->moveToDLQ($line);
                    }
                    
                } catch (\Throwable $e) {
                    // Corrupted line or error, skip or move to DLQ
                    echo "Skipping corrupted queue line: {$e->getMessage()}\n";
                    continue;
                }
            }
            
            // Add retry items back
            $remaining = array_merge($remaining, $retryLater);
            
            // Write remaining items back
            try {
                if (!empty($remaining)) {
                    file_put_contents($this->queuePath, implode("\n", $remaining) . "\n");
                } else {
                    // Queue empty, delete file
                    @unlink($this->queuePath);
                }
            } catch (\Throwable $e) {
                echo "Failed to write queue file: {$e->getMessage()}\n";
            }
            
            flock($lockHandle, LOCK_UN);
            fclose($lockHandle);
            
        } catch (\Throwable $e) {
            if ($lockHandle) {
                flock($lockHandle, LOCK_UN);
                fclose($lockHandle);
            }
            echo "Error during queue drain: {$e->getMessage()}\n";
        }
    }
    
    private function moveToDLQ(string $data) : void {
        try {
            @file_put_contents($this->dlqPath, $data . "\n", FILE_APPEND);
        } catch (\Throwable $e) {
            echo "Cannot write to dead letter queue: {$e->getMessage()}\n";
        }
    }
}

