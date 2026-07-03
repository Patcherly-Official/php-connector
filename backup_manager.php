<?php
/**
 * Agent-Side Backup Manager (PHP)
 * Manages versioned backups with checksums, compression, and integrity verification.
 */

class AgentBackupManager {
    private $backupRoot;
    private $allowedTargetRoots = [];
    
    /**
     * Initialize backup manager.
     * 
     * @param string|null $backupRoot Root directory for backups. If null, uses:
     *   - PATCHERLY_BACKUP_ROOT environment variable
     *   - ../backups/ (outside webroot, default)
     */
    public function __construct($backupRoot = null) {
        if ($backupRoot === null) {
            $backupRoot = getenv('PATCHERLY_BACKUP_ROOT') ?: '../backups';
        }
        $this->backupRoot = realpath($backupRoot) ?: $backupRoot;
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
        if (!is_dir($this->backupRoot)) {
            mkdir($this->backupRoot, 0700, true);  // Restrictive permissions
        }
        
        // Ensure backup directory is protected from direct web access
        $this->ensureBackupProtection();
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
    
    /**
     * Ensure backup directory is protected from direct access.
     */
    private function ensureBackupProtection() {
        $htaccess_file = $this->backupRoot . DIRECTORY_SEPARATOR . '.htaccess';
        
        // Create .htaccess if it doesn't exist
        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# Deny all direct access to backup files\n";
            $htaccess_content .= "Order Deny,Allow\n";
            $htaccess_content .= "Deny from all\n";
            $htaccess_content .= "\n# Prevent directory listing\n";
            $htaccess_content .= "Options -Indexes\n";
            
            @file_put_contents($htaccess_file, $htaccess_content);
        }
        
        // Also create index.php to prevent directory listing
        $index_file = $this->backupRoot . DIRECTORY_SEPARATOR . 'index.php';
        if (!file_exists($index_file)) {
            @file_put_contents($index_file, "<?php\n// Silence is golden.\n");
        }
    }
    
    /**
     * Create a versioned backup with checksums.
     * 
     * @param string $errorId Unique error identifier
     * @param array $files List of file paths to backup
     * @param bool $compress Whether to compress backup files
     * @param bool $verify Whether to verify backup integrity after creation
     * @return array BackupMetadata array
     */
    public function createBackup($errorId, $files, $compress = true, $verify = true) {
        $timestamp = date('Y-m-d\TH-i-s\Z', time());
        $backupDir = $this->backupRoot . DIRECTORY_SEPARATOR . $errorId . DIRECTORY_SEPARATOR . $timestamp;
        
        if (!is_dir($backupDir)) {
            mkdir($backupDir, 0755, true);
        }
        
        error_log("Creating backup in {$backupDir} for " . count($files) . " file(s)");
        
        $backupManifest = [];
        
        foreach ($files as $filePath) {
            try {
                if (!$this->isPathWithinAllowedRoots($filePath)) {
                    error_log("Skipping backup outside allowed target roots: {$filePath}");
                    continue;
                }
                // Check if file exists
                if (!file_exists($filePath)) {
                    error_log("File not found, skipping: {$filePath}");
                    continue;
                }
                
                // Read file content
                $content = file_get_contents($filePath);
                if ($content === false) {
                    throw new Exception("Failed to read file: {$filePath}");
                }
                
                // Calculate checksum
                $checksum = hash('sha256', $content);
                $fileSize = strlen($content);
                
                // Determine backup filename
                $backupFileName = basename($filePath);
                $backupFile = $backupDir . DIRECTORY_SEPARATOR . $backupFileName;
                
                // Write backup file
                file_put_contents($backupFile, $content);
                
                $finalBackupFile = $backupFile;
                $finalSize = $fileSize;
                $wasCompressed = false;
                
                // Compress if requested
                if ($compress && $fileSize > 0) {
                    $compressedFile = $backupFile . '.gz';
                    $compressed = gzencode($content, 9);
                    file_put_contents($compressedFile, $compressed);
                    // Remove uncompressed file
                    unlink($backupFile);
                    $finalBackupFile = $compressedFile;
                    $finalSize = strlen($compressed);
                    $wasCompressed = true;
                }
                
                $backupManifest[$filePath] = [
                    'checksum' => $checksum,
                    'size' => $finalSize,
                    'backup_path' => $finalBackupFile,
                    'original_size' => $fileSize,
                    'compressed' => $wasCompressed
                ];
                
                error_log("Backed up {$filePath} -> {$finalBackupFile} (checksum: " . substr($checksum, 0, 16) . "...)");
                
            } catch (Exception $e) {
                error_log("Failed to backup file {$filePath}: " . $e->getMessage());
                // Continue with other files
                continue;
            }
        }
        
        if (empty($backupManifest)) {
            throw new Exception('No files were successfully backed up');
        }
        
        // Write manifest
        $manifestPath = $backupDir . DIRECTORY_SEPARATOR . 'manifest.json';
        $manifestData = [
            'error_id' => $errorId,
            'created_at' => $timestamp,
            'files' => $backupManifest,
            'backup_version' => 1
        ];
        file_put_contents($manifestPath, json_encode($manifestData, JSON_PRETTY_PRINT));
        
        // Verify backup integrity if requested
        $verified = true;
        if ($verify) {
            $verified = $this->verifyBackupIntegrity($backupDir, $backupManifest);
        }
        
        $metadata = [
            'error_id' => $errorId,
            'backup_dir' => $backupDir,
            'files' => array_keys($backupManifest),
            'manifest' => $backupManifest,
            'created_at' => $timestamp,
            'verified' => $verified
        ];
        
        error_log("Backup created successfully: {$backupDir} (verified: " . ($verified ? 'true' : 'false') . ")");
        return $metadata;
    }
    
    /**
     * Verify backup integrity by checking checksums.
     * 
     * @param string $backupDir Path to backup directory
     * @param array $manifest Backup manifest
     * @return bool True if all checksums match
     */
    private function verifyBackupIntegrity($backupDir, $manifest) {
        error_log("Verifying backup integrity in {$backupDir}");
        
        try {
            foreach ($manifest as $filePath => $fileInfo) {
                $backupFilePath = $fileInfo['backup_path'];
                $expectedChecksum = $fileInfo['checksum'];
                
                if (!file_exists($backupFilePath)) {
                    error_log("Backup file not found: {$backupFilePath}");
                    return false;
                }
                
                // Read and decompress if needed
                if ($fileInfo['compressed']) {
                    $compressed = file_get_contents($backupFilePath);
                    $content = gzdecode($compressed);
                } else {
                    $content = file_get_contents($backupFilePath);
                }
                
                // Verify checksum
                $actualChecksum = hash('sha256', $content);
                
                if ($actualChecksum !== $expectedChecksum) {
                    error_log(
                        "Checksum mismatch for {$filePath}: " .
                        "expected " . substr($expectedChecksum, 0, 16) . "..., " .
                        "got " . substr($actualChecksum, 0, 16) . "..."
                    );
                    return false;
                }
                
                error_log("Verified {$filePath} (checksum: " . substr($expectedChecksum, 0, 16) . "...)");
            }
            
            error_log('Backup integrity verification passed');
            return true;
            
        } catch (Exception $e) {
            error_log('Backup integrity verification failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Restore files from a backup.
     * 
     * @param string $backupDir Path to backup directory
     * @param array|null $targetFiles Optional mapping of backup file paths to restore targets
     * @return bool True if restore was successful
     */
    public function restoreBackup($backupDir, $targetFiles = null) {
        if (!is_dir($backupDir)) {
            error_log("Backup directory not found: {$backupDir}");
            return false;
        }
        
        $manifestPath = $backupDir . DIRECTORY_SEPARATOR . 'manifest.json';
        if (!file_exists($manifestPath)) {
            error_log("Manifest not found in backup: {$manifestPath}");
            return false;
        }
        
        try {
            // Load manifest
            $manifestContent = file_get_contents($manifestPath);
            $manifestData = json_decode($manifestContent, true);
            $files = $manifestData['files'] ?? [];
            
            error_log("Restoring backup from {$backupDir}");
            
            // Restore each file
            foreach ($files as $originalPath => $fileInfo) {
                $backupFilePath = $fileInfo['backup_path'];
                
                // Determine target file path
                if ($targetFiles && isset($targetFiles[$originalPath])) {
                    $targetPath = $targetFiles[$originalPath];
                } else {
                    $targetPath = $originalPath;
                }
                if (!$this->isPathWithinAllowedRoots($targetPath)) {
                    error_log("Refusing restore outside allowed target roots: {$targetPath}");
                    return false;
                }
                
                // Ensure target directory exists
                $targetDir = dirname($targetPath);
                if (!is_dir($targetDir)) {
                    mkdir($targetDir, 0755, true);
                }
                
                // Read and decompress if needed
                if ($fileInfo['compressed']) {
                    $compressed = file_get_contents($backupFilePath);
                    $content = gzdecode($compressed);
                } else {
                    $content = file_get_contents($backupFilePath);
                }
                
                // Write restored file
                file_put_contents($targetPath, $content);
                
                // Verify restored file checksum
                $restoredChecksum = hash('sha256', $content);
                $expectedChecksum = $fileInfo['checksum'];
                
                if ($restoredChecksum !== $expectedChecksum) {
                    error_log(
                        "Restored file checksum mismatch for {$originalPath}: " .
                        "expected " . substr($expectedChecksum, 0, 16) . "..., " .
                        "got " . substr($restoredChecksum, 0, 16) . "..."
                    );
                    return false;
                }
                
                error_log("Restored {$originalPath} -> {$targetPath}");
            }
            
            error_log('Backup restore completed successfully');
            return true;
            
        } catch (Exception $e) {
            error_log('Backup restore failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * List available backups.
     * 
     * @param string|null $errorId Optional filter by error_id
     * @return array List of backup metadata arrays
     */
    public function listBackups($errorId = null) {
        $backups = [];
        
        $errorDirs = [];
        if ($errorId) {
            $errorDir = $this->backupRoot . DIRECTORY_SEPARATOR . $errorId;
            if (is_dir($errorDir)) {
                $errorDirs[] = $errorDir;
            } else {
                return [];
            }
        } else {
            $entries = scandir($this->backupRoot);
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') continue;
                $entryPath = $this->backupRoot . DIRECTORY_SEPARATOR . $entry;
                if (is_dir($entryPath)) {
                    $errorDirs[] = $entryPath;
                }
            }
        }
        
        foreach ($errorDirs as $errorDir) {
            $entries = scandir($errorDir);
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') continue;
                $backupDir = $errorDir . DIRECTORY_SEPARATOR . $entry;
                if (is_dir($backupDir)) {
                    $manifestPath = $backupDir . DIRECTORY_SEPARATOR . 'manifest.json';
                    if (file_exists($manifestPath)) {
                        try {
                            $manifestContent = file_get_contents($manifestPath);
                            $manifestData = json_decode($manifestContent, true);
                            $backups[] = [
                                'error_id' => $manifestData['error_id'] ?? null,
                                'backup_dir' => $backupDir,
                                'created_at' => $manifestData['created_at'] ?? null,
                                'files_count' => count($manifestData['files'] ?? [])
                            ];
                        } catch (Exception $e) {
                            error_log("Failed to read manifest from {$manifestPath}: " . $e->getMessage());
                        }
                    }
                }
            }
        }
        
        return $backups;
    }
    
    // Note: cleanupOldBackups() and its private deleteDirectory() helper were
    // removed in v1.44. Connector pre-apply backups are intentionally
    // customer-managed with indefinite retention (see help/connectors/php.md
    // and help/error-management/rollback.md). The Patcherly app's own DB-
    // backup retention (server/app/services/db_backup.py) is a separate
    // workflow and is unaffected. Reintroduce only if a tenant or auditor
    // requirement makes connector-side pruning concretely necessary.
}

