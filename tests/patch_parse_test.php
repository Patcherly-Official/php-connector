<?php
/**
 * CLI: php connectors/php/tests/patch_parse_test.php
 */
require_once dirname(__DIR__) . '/patch_applicator.php';

$patch = <<<PATCH
--- a/foo.txt
+++ b/foo.txt
@@ -1,2 +1,3 @@
 line1
-line2
+line2b
+line3
@@ -5,1 +6,2 @@
 ctx
-old
+new
PATCH;

$ap = new PatchApplicator();
$fps = $ap->parsePatch($patch);
if (count($fps) !== 1) {
    fwrite(STDERR, "Expected 1 file patch, got " . count($fps) . "\n");
    exit(1);
}
if (count($fps[0]->hunks) !== 2) {
    fwrite(STDERR, "Expected 2 hunks, got " . count($fps[0]->hunks) . "\n");
    exit(1);
}

try {
    $ap->parsePatch('not a unified diff');
    fwrite(STDERR, "Expected PatchParseError\n");
    exit(1);
} catch (PatchParseError $e) {
    // ok
}

echo "patch_parse_test.php: OK\n";
