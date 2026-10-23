<?php
/**
 * PHP framework detection for ingest + context upload.
 *
 * Prefer runtime class_exists when the app is loaded; otherwise use filesystem
 * cues (artisan / composer.json / vendor/) so the standalone agent can stamp
 * code_framework without bootstrapping Laravel.
 */

if (!function_exists('patcherly_php_framework_from_runtime')) {
    function patcherly_php_framework_from_runtime(): ?string {
        if (class_exists('Illuminate\\Foundation\\Application')) {
            return 'laravel';
        }
        if (class_exists('Symfony\\Component\\HttpKernel\\Kernel')) {
            return 'symfony';
        }
        if (defined('CI_VERSION')) {
            return 'codeigniter';
        }
        if (class_exists('yii\\base\\Application')) {
            return 'yii';
        }
        if (class_exists('Zend\\Version\\Version')) {
            return 'zend';
        }
        return null;
    }
}

if (!function_exists('patcherly_composer_requires_package')) {
    /**
     * @return bool True when composer.json require/require-dev lists $package.
     */
    function patcherly_composer_requires_package(string $root, string $package): bool {
        $composer = rtrim(str_replace('\\', '/', $root), '/') . '/composer.json';
        if (!is_file($composer)) {
            return false;
        }
        $raw = @file_get_contents($composer);
        if (!is_string($raw) || $raw === '') {
            return false;
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            return false;
        }
        foreach (['require', 'require-dev'] as $key) {
            if (!empty($data[$key]) && is_array($data[$key]) && array_key_exists($package, $data[$key])) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('patcherly_php_framework_roots_from_path')) {
    /**
     * Candidate app roots from an error file path (…/vendor/… → app root)
     * plus parent walk for artisan/composer.json and PATCHERLY_TARGET_ROOTS.
     *
     * @return list<string>
     */
    function patcherly_php_framework_roots_from_path(?string $hintPath): array {
        $roots = [];
        if (is_string($hintPath) && $hintPath !== '') {
            $norm = str_replace('\\', '/', $hintPath);
            if (preg_match('#^(.*?)/vendor/#', $norm, $m) && is_string($m[1]) && $m[1] !== '') {
                $roots[] = $m[1];
            }
            $cur = dirname($hintPath);
            for ($i = 0; $i < 8; $i++) {
                if (!is_string($cur) || $cur === '' || $cur === '/' || $cur === '\\') {
                    break;
                }
                $base = rtrim(str_replace('\\', '/', $cur), '/');
                if (is_file($base . '/artisan') || is_file($base . '/composer.json') || is_file($base . '/bin/console')) {
                    $roots[] = $base;
                }
                $parent = dirname($cur);
                if ($parent === $cur) {
                    break;
                }
                $cur = $parent;
            }
        }
        $envRoots = getenv('PATCHERLY_TARGET_ROOTS');
        if (is_string($envRoots) && $envRoots !== '') {
            $sep = PATH_SEPARATOR;
            $normalized = str_replace(';', $sep, $envRoots);
            foreach (explode($sep, $normalized) as $part) {
                $p = trim($part);
                if ($p !== '') {
                    $roots[] = $p;
                }
            }
        }
        return $roots;
    }
}

if (!function_exists('patcherly_php_framework_from_filesystem')) {
    function patcherly_php_framework_from_filesystem(string $root): ?string {
        $root = rtrim(str_replace('\\', '/', $root), '/');
        if ($root === '' || !is_dir($root)) {
            return null;
        }
        $hasArtisan = is_file($root . '/artisan');
        $hasLaravelVendor = is_dir($root . '/vendor/laravel/framework');
        if ($hasArtisan && ($hasLaravelVendor || patcherly_composer_requires_package($root, 'laravel/framework'))) {
            return 'laravel';
        }
        if (is_file($root . '/bin/console') && (
            is_dir($root . '/vendor/symfony/http-kernel')
            || patcherly_composer_requires_package($root, 'symfony/framework-bundle')
            || patcherly_composer_requires_package($root, 'symfony/http-kernel')
        )) {
            return 'symfony';
        }
        // Filesystem-only CI cue (runtime CI_VERSION is handled above).
        if (is_file($root . '/system/core/CodeIgniter.php')) {
            return 'codeigniter';
        }
        if (is_file($root . '/yii') || is_dir($root . '/vendor/yiisoft/yii2')) {
            return 'yii';
        }
        return null;
    }
}

if (!function_exists('patcherly_detect_php_framework')) {
    /**
     * @param string|null $hintPath Optional throw-site path to infer app root.
     */
    function patcherly_detect_php_framework(?string $hintPath = null): ?string {
        $fromRuntime = patcherly_php_framework_from_runtime();
        if ($fromRuntime !== null) {
            return $fromRuntime;
        }
        $roots = patcherly_php_framework_roots_from_path($hintPath);
        $cwd = getcwd();
        if (is_string($cwd) && $cwd !== '') {
            $roots[] = $cwd;
        }
        $seen = [];
        foreach ($roots as $root) {
            $key = strtolower(rtrim(str_replace('\\', '/', (string) $root), '/'));
            if ($key === '' || isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $fw = patcherly_php_framework_from_filesystem((string) $root);
            if ($fw !== null) {
                return $fw;
            }
        }
        return null;
    }
}
