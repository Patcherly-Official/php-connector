<?php
declare(strict_types=1);

/**
 * Single PATCHERLY_CONNECTOR_VERSION anchor for php_agent.php and patcherly_cli.php.
 * Bumped by setup/git-hooks/bump_version_from_branch.py and update-release-latest.yml.
 */
if (!defined('PATCHERLY_CONNECTOR_VERSION')) {
    define('PATCHERLY_CONNECTOR_VERSION', '2.3.3');
}
