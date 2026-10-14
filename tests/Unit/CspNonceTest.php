<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for credentials_csp_nonce().
 *
 * The helper has two outcomes that hinge on whether Cacti's global
 * CactiSecureHeaders class is present. A single PHP process can only ever
 * see the class as present or absent, so the class-present outcome is
 * exercised in an isolated child process that defines a controlled double.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

test('csp nonce returns an empty string when CactiSecureHeaders is unavailable', function () {
	if (class_exists('CactiSecureHeaders')) {
		$this->markTestSkipped('CactiSecureHeaders is present in this runtime; the delegation path is covered by the isolated-process test.');
	}

	expect(credentials_csp_nonce())->toBe('');
});

test('csp nonce helper is declared to return a string', function () {
	$ref = new ReflectionFunction('credentials_csp_nonce');

	expect((string) $ref->getReturnType())->toBe('string');
});

test('csp nonce delegates to CactiSecureHeaders when the class is available', function () {
	$wrapper = realpath(__DIR__ . '/../../setup.php');
	expect($wrapper)->not->toBeFalse();

	$bootstrap = realpath(__DIR__ . '/../bootstrap-unit.php');

	$script = <<<'CHILD'
<?php
error_reporting(0);
ini_set('display_errors', '0');

class CactiSecureHeaders {
	public static function getNonceAttribute(): string {
		return ' nonce="pest-controlled-double"';
	}
}

if (isset($argv[2]) && $argv[2] !== '' && is_file($argv[2])) {
	try { require $argv[2]; } catch (\Throwable $e) { /* no Cacti host locally */ }
}

require $argv[1];

echo "<<<" . credentials_csp_nonce() . ">>>";
CHILD;

	$tmp = tempnam(sys_get_temp_dir(), 'csp_');
	expect($tmp)->not->toBeFalse();

	try {
		file_put_contents($tmp, $script);

		$command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($tmp) . ' ' . escapeshellarg($wrapper) . ' ' . escapeshellarg($bootstrap === false ? '' : $bootstrap);
		$output  = shell_exec($command);

		expect($output)->not->toBeNull();

		preg_match('/<<<(.*)>>>/s', (string) $output, $matches);
		expect($matches)->toHaveKey(1);
		expect($matches[1])->toBe(' nonce="pest-controlled-double"');
	} finally {
		@unlink($tmp);
	}
});
