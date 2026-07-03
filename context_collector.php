<?php
/**
 * PHP Context Collector
 * 
 * Collects environment information for AI analysis:
 * - PHP version and configuration
 * - Server information
 * - Installed extensions
 * - Framework detection (Laravel, Symfony, CodeIgniter, etc.)
 * - Composer packages (if available)
 * - Database connections
 */

class Patcherly_PHPContextCollector {
    
    private $cache_dir;

    public function __construct(?string $cache_dir = null) {
        // Keep backward compatibility with existing __init__ usage.
        $this->__init__($cache_dir);
    }
    
    public function __init__(?string $cache_dir = null) {
        $default = getenv('PATCHERLY_CACHE_DIR') ?: '.patcherly_cache';
        $this->cache_dir = rtrim($cache_dir ?? $default, '/');
        
        // Create cache directory if it doesn't exist
        if (!is_dir($this->cache_dir)) {
            mkdir($this->cache_dir, 0755, true);
        }
        
        // Ensure cache directory is protected
        $this->ensure_cache_protection();
    }
    
    /**
     * Ensure cache directory is protected from direct access.
     */
    private function ensure_cache_protection() {
        $htaccess_file = $this->cache_dir . '/.htaccess';
        
        // Create .htaccess if it doesn't exist
        if (!file_exists($htaccess_file)) {
            $htaccess_content = "# Deny all direct access to context files\n";
            $htaccess_content .= "Order Deny,Allow\n";
            $htaccess_content .= "Deny from all\n";
            $htaccess_content .= "\n# Prevent directory listing\n";
            $htaccess_content .= "Options -Indexes\n";
            
            @file_put_contents($htaccess_file, $htaccess_content);
        }
        
        // Also create index.php to prevent directory listing
        $index_file = $this->cache_dir . '/index.php';
        if (!file_exists($index_file)) {
            @file_put_contents($index_file, "<?php\n// Silence is golden.\n");
        }
    }
    
    /**
     * Collect all context information
     */
    public function collect_all(): array {
        return [
            'server' => $this->collect_server_info(),
            'php' => $this->collect_php_info(),
            'extensions' => $this->collect_extensions(),
            'framework' => $this->detect_framework(),
            'composer' => $this->collect_composer_packages(),
            'database' => $this->detect_database(),
            'collected_at' => date('Y-m-d H:i:s'),
        ];
    }
    
    /**
     * Collect server information
     */
    private function collect_server_info(): array {
        return [
            'os' => PHP_OS,
            'sapi' => PHP_SAPI,
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? null,
            'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? null,
        ];
    }
    
    /**
     * Collect PHP information
     */
    private function collect_php_info(): array {
        return [
            'version' => PHP_VERSION,
            'version_id' => PHP_VERSION_ID,
            'memory_limit' => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
            'upload_max_filesize' => ini_get('upload_max_filesize'),
            'post_max_size' => ini_get('post_max_size'),
            'error_reporting' => error_reporting(),
            'display_errors' => ini_get('display_errors'),
        ];
    }
    
    /**
     * Collect installed PHP extensions
     */
    private function collect_extensions(): array {
        return get_loaded_extensions();
    }
    
    /**
     * Detect which framework is being used
     */
    private function detect_framework(): array {
        $framework = [
            'detected' => null,
            'version' => null,
        ];
        
        // Check for Laravel
        if (class_exists('Illuminate\Foundation\Application')) {
            $framework['detected'] = 'laravel';
            if (defined('Illuminate\Foundation\Application::VERSION')) {
                $framework['version'] = Illuminate\Foundation\Application::VERSION;
            }
        }
        // Check for Symfony
        elseif (class_exists('Symfony\Component\HttpKernel\Kernel')) {
            $framework['detected'] = 'symfony';
            if (defined('Symfony\Component\HttpKernel\Kernel::VERSION')) {
                $framework['version'] = Symfony\Component\HttpKernel\Kernel::VERSION;
            }
        }
        // Check for CodeIgniter
        elseif (defined('CI_VERSION')) {
            $framework['detected'] = 'codeigniter';
            $framework['version'] = CI_VERSION;
        }
        // Check for Yii
        elseif (class_exists('yii\base\Application')) {
            $framework['detected'] = 'yii';
            if (defined('Yii::VERSION')) {
                $framework['version'] = Yii::VERSION;
            }
        }
        // Check for Zend Framework
        elseif (class_exists('Zend\Version\Version')) {
            $framework['detected'] = 'zend';
            $framework['version'] = Zend\Version\Version::VERSION;
        }
        
        return $framework;
    }
    
    /**
     * Collect Composer packages (if composer.json exists)
     */
    private function collect_composer_packages(): array {
        $composer_file = getcwd() . '/composer.json';
        if (!file_exists($composer_file)) {
            return ['available' => false];
        }
        
        try {
            $composer_data = json_decode(file_get_contents($composer_file), true);
            $packages = [];
            
            // Get require packages
            if (isset($composer_data['require'])) {
                foreach ($composer_data['require'] as $package => $version) {
                    $packages[] = [
                        'name' => $package,
                        'version_constraint' => $version,
                    ];
                }
            }
            
            return [
                'available' => true,
                'packages' => $packages,
            ];
        } catch (Exception $e) {
            return [
                'available' => true,
                'error' => 'Failed to parse composer.json',
            ];
        }
    }
    
    /**
     * Detect database connections
     */
    private function detect_database(): array {
        $databases = [];
        
        // Check for PDO
        $pdo_drivers = extension_loaded('pdo') ? PDO::getAvailableDrivers() : [];
        foreach ($pdo_drivers as $driver) {
            $databases[$driver] = ['available' => true, 'via' => 'pdo'];
        }
        
        // Check for mysqli
        if (extension_loaded('mysqli')) {
            $databases['mysql'] = ['available' => true, 'via' => 'mysqli'];
        }
        
        // Check for MongoDB
        if (extension_loaded('mongodb')) {
            $databases['mongodb'] = ['available' => true];
        }
        
        return $databases;
    }
    
    /**
     * Save context to JSON files
     */
    public function save_context(): bool {
        $context = $this->collect_all();
        
        // Save full context
        $full_context_file = $this->cache_dir . '/php-context.json';
        $result1 = file_put_contents($full_context_file, json_encode($context, JSON_PRETTY_PRINT));
        
        // Save server context separately
        $server_context = [
            'server' => $context['server'],
            'collected_at' => $context['collected_at'],
        ];
        $server_context_file = $this->cache_dir . '/server-context.json';
        $result2 = file_put_contents($server_context_file, json_encode($server_context, JSON_PRETTY_PRINT));
        
        return $result1 !== false && $result2 !== false;
    }
    
    /**
     * Load context from JSON files
     */
    public function load_context(): ?array {
        $context_file = $this->cache_dir . '/php-context.json';
        if (!file_exists($context_file)) {
            return null;
        }
        
        $content = file_get_contents($context_file);
        return json_decode($content, true);
    }
    
    /**
     * Check if context has changed since last collection
     */
    public function has_changed(): bool {
        $old_context = $this->load_context();
        if (!$old_context) {
            return true;
        }
        
        $new_context = $this->collect_all();
        
        // Compare key fields
        $key_fields = ['extensions', 'framework', 'composer', 'database'];
        
        foreach ($key_fields as $field) {
            $old_value = $old_context[$field] ?? null;
            $new_value = $new_context[$field] ?? null;
            
            if (json_encode($old_value) !== json_encode($new_value)) {
                return true;
            }
        }
        
        return false;
    }

    // Canonical connector parity aliases (non-breaking).
    public function collectAll(): array {
        return $this->collect_all();
    }

    public function saveContext(): bool {
        return $this->save_context();
    }

    public function loadContext(): ?array {
        return $this->load_context();
    }

    public function hasChanged(): bool {
        return $this->has_changed();
    }
}

