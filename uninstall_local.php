<?php
/**
 * Local wipe helpers for `patcherly uninstall` (PHP connector).
 * Parity with connectors/python/uninstall_local.py.
 */

if (!function_exists('patcherly_uninstall_is_safe_wipe_target')) {
    /**
     * Refuse recursive wipe of filesystem root, install dir, or their ancestors.
     *
     * @param list<string> $protect
     */
    function patcherly_uninstall_is_safe_wipe_target(
        string $candidate,
        string $installDir,
        array $protect = []
    ): bool {
        $target = realpath($candidate);
        if ($target === false) {
            $target = $candidate;
            if (!preg_match('#^(/|[A-Za-z]:[\\\\/])#', $target)) {
                return false;
            }
            // Normalize .. segments without requiring the path to exist yet.
            $parts = preg_split('#[\\\\/]+#', $target);
            $norm = [];
            foreach ($parts as $part) {
                if ($part === '' || $part === '.') {
                    continue;
                }
                if ($part === '..') {
                    array_pop($norm);
                    continue;
                }
                $norm[] = $part;
            }
            if (preg_match('#^([A-Za-z]:)#', $candidate, $m)) {
                $target = $m[1] . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $norm);
            } else {
                $target = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $norm);
            }
        }
        $install = realpath($installDir);
        if ($install === false) {
            $install = rtrim($installDir, "/\\");
        }
        $target = rtrim(str_replace('\\', '/', $target), '/');
        $install = rtrim(str_replace('\\', '/', $install), '/');
        if ($target === '' || $target === '/' || preg_match('#^[A-Za-z]:$#', $target)) {
            return false;
        }
        if ($target === $install) {
            return false;
        }
        if (strpos($install . '/', $target . '/') === 0) {
            return false;
        }
        foreach ($protect as $p) {
            $protected = realpath((string) $p);
            if ($protected === false) {
                $protected = rtrim(str_replace('\\', '/', (string) $p), '/');
            } else {
                $protected = rtrim(str_replace('\\', '/', $protected), '/');
            }
            if ($protected !== '' && $protected !== $target
                && strpos($protected . '/', $target . '/') === 0
            ) {
                return false;
            }
        }
        return true;
    }
}

if (!function_exists('patcherly_uninstall_resolve_paths')) {
    /**
     * @return array<string,string>
     */
    function patcherly_uninstall_resolve_paths(?string $cwd = null): array
    {
        $root = $cwd !== null ? realpath($cwd) : getcwd();
        if (!is_string($root) || $root === '') {
            $root = getcwd() ?: '.';
        }
        $credEnv = trim((string) (getenv('PATCHERLY_CREDENTIAL_FILE') ?: ''));
        if ($credEnv !== '') {
            $cred = $credEnv;
        } else {
            $home = getenv('HOME') ?: (getenv('USERPROFILE') ?: '');
            $cred = rtrim((string) $home, "/\\") . DIRECTORY_SEPARATOR . '.patcherly'
                . DIRECTORY_SEPARATOR . 'credentials.json';
        }
        $queue = getenv('PATCHERLY_QUEUE_PATH') ?: ($root . DIRECTORY_SEPARATOR . 'patcherly_queue.jsonl');
        if (!preg_match('#^(/|[A-Za-z]:[\\\\/])#', $queue)) {
            $queue = $root . DIRECTORY_SEPARATOR . $queue;
        }
        $ids = getenv('PATCHERLY_IDS_PATH') ?: ($root . DIRECTORY_SEPARATOR . 'patcherly_ids.json');
        if (!preg_match('#^(/|[A-Za-z]:[\\\\/])#', $ids)) {
            $ids = $root . DIRECTORY_SEPARATOR . $ids;
        }
        $backup = getenv('PATCHERLY_BACKUP_ROOT') ?: ($root . DIRECTORY_SEPARATOR . '.patcherly_backups');
        if (!preg_match('#^(/|[A-Za-z]:[\\\\/])#', $backup)) {
            $backup = $root . DIRECTORY_SEPARATOR . $backup;
        }
        $cache = getenv('PATCHERLY_CACHE_DIR') ?: ($root . DIRECTORY_SEPARATOR . '.patcherly_cache');
        if (!preg_match('#^(/|[A-Za-z]:[\\\\/])#', $cache)) {
            $cache = $root . DIRECTORY_SEPARATOR . $cache;
        }
        $dlq = dirname($queue) . DIRECTORY_SEPARATOR . pathinfo($queue, PATHINFO_FILENAME) . '.dlq.jsonl';
        return [
            'install_dir' => $root,
            'credentials' => $cred,
            'credentials_dir' => dirname($cred),
            'queue' => $queue,
            'dlq' => $dlq,
            'ids' => $ids,
            'backup_root' => $backup,
            'cache_dir' => $cache,
        ];
    }
}

if (!function_exists('patcherly_uninstall_stop_agent_best_effort')) {
    /**
     * @return list<string>
     */
    function patcherly_uninstall_stop_agent_best_effort(): array
    {
        $notes = [];
        $attempts = [
            ['systemctl', 'stop', 'patcherly-connector'],
            ['systemctl', '--user', 'stop', 'patcherly-connector'],
        ];
        foreach ($attempts as $args) {
            $cmd = implode(' ', array_map('escapeshellarg', $args));
            $out = [];
            $code = 1;
            if (!function_exists('exec')) {
                $notes[] = '`exec` disabled; could not stop systemd unit';
                break;
            }
            @exec($cmd . ' 2>&1', $out, $code);
            if ($code === 0) {
                $notes[] = 'stopped via `' . implode(' ', $args) . '`';
            } else {
                $tip = isset($out[0]) ? (string) $out[0] : ('exit ' . $code);
                $notes[] = '`' . implode(' ', $args) . '` skipped (' . $tip . ')';
            }
        }
        return $notes;
    }
}

if (!function_exists('patcherly_uninstall_safe_unlink')) {
    /**
     * @param list<string> $removed
     * @param list<string> $left
     */
    function patcherly_uninstall_safe_unlink(string $path, array &$removed, array &$left): void
    {
        if (!file_exists($path) && !is_link($path)) {
            return;
        }
        if (is_dir($path) && !is_link($path)) {
            $left[] = $path . ' (unexpected directory; left in place)';
            return;
        }
        if (@unlink($path)) {
            $removed[] = $path;
        } else {
            $left[] = $path . ' (could not remove)';
        }
    }
}

if (!function_exists('patcherly_uninstall_rmtree')) {
    /**
     * @param list<string> $removed
     * @param list<string> $left
     * @param list<string> $protect
     */
    function patcherly_uninstall_rmtree(
        string $path,
        array &$removed,
        array &$left,
        string $installDir = '',
        array $protect = []
    ): void {
        if ($installDir !== ''
            && !patcherly_uninstall_is_safe_wipe_target($path, $installDir, $protect)
        ) {
            $left[] = $path . ' (refused: unsafe wipe target)';
            return;
        }
        if (!file_exists($path)) {
            return;
        }
        if (!is_dir($path)) {
            patcherly_uninstall_safe_unlink($path, $removed, $left);
            return;
        }
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $item) {
            $p = $item->getPathname();
            if ($item->isDir()) {
                @rmdir($p);
            } else {
                @unlink($p);
            }
        }
        if (@rmdir($path)) {
            $removed[] = rtrim($path, "/\\") . DIRECTORY_SEPARATOR;
        } else {
            $left[] = $path . ' (could not remove)';
        }
    }
}

if (!function_exists('patcherly_uninstall_wipe_local')) {
    /**
     * @return array{0:list<string>,1:list<string>}
     */
    function patcherly_uninstall_wipe_local(bool $removeBackups, ?string $cwd = null): array
    {
        $paths = patcherly_uninstall_resolve_paths($cwd);
        $removed = [];
        $left = [];
        $protect = [
            $paths['credentials'],
            $paths['queue'],
            $paths['dlq'],
            $paths['ids'],
        ];
        foreach (['queue', 'dlq', 'ids'] as $key) {
            patcherly_uninstall_safe_unlink($paths[$key], $removed, $left);
        }
        patcherly_uninstall_rmtree(
            $paths['cache_dir'],
            $removed,
            $left,
            $paths['install_dir'],
            $protect
        );
        patcherly_uninstall_safe_unlink($paths['credentials'], $removed, $left);
        $credDir = $paths['credentials_dir'];
        if (is_dir($credDir)) {
            $entries = @scandir($credDir);
            if (is_array($entries) && count(array_diff($entries, ['.', '..'])) === 0) {
                if (@rmdir($credDir)) {
                    $removed[] = rtrim($credDir, "/\\") . DIRECTORY_SEPARATOR;
                }
            }
        }
        if ($removeBackups) {
            patcherly_uninstall_rmtree(
                $paths['backup_root'],
                $removed,
                $left,
                $paths['install_dir'],
                $protect
            );
        } elseif (file_exists($paths['backup_root'])) {
            $left[] = rtrim($paths['backup_root'], "/\\") . DIRECTORY_SEPARATOR . ' (pre-apply backups kept)';
        }
        $left[] = rtrim($paths['install_dir'], "/\\") . DIRECTORY_SEPARATOR
            . ' (install directory — remove manually if desired)';
        $left[] = 'systemd unit patcherly-connector.service (disable/remove manually if installed)';
        return [$removed, $left];
    }
}

if (!function_exists('patcherly_uninstall_prompt_remove_backups')) {
    function patcherly_uninstall_prompt_remove_backups(bool $keepBackups = false, bool $removeBackups = false): bool
    {
        if ($removeBackups) {
            return true;
        }
        if ($keepBackups) {
            return false;
        }
        if (!defined('STDIN') || !function_exists('stream_isatty') || !@stream_isatty(STDIN)) {
            return false;
        }
        fwrite(STDERR, "Remove pre-apply backups too? [y/N] ");
        $ans = fgets(STDIN);
        if ($ans === false) {
            return false;
        }
        $a = strtolower(trim($ans));
        return $a === 'y' || $a === 'yes';
    }
}
