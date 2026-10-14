<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the pre-1.2.32 encryption polyfill in includes/functions.php
 * (cacti_secret_key / cacti_encrypt_secret* / cacti_decrypt_secret*). The unit
 * bootstrap sets CACTI_VERSION below 1.2.32, so these are the REAL fallback
 * implementations - not doubles - exercised here against a settings-backed key.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

beforeEach(function () {
	credentials_test_reset_key();
});

it('defines the fallback secret functions and GCM constants on pre-1.2.32 Cacti', function () {
	expect(function_exists('cacti_secret_key'))->toBeTrue()
		->and(function_exists('cacti_encrypt_secret'))->toBeTrue()
		->and(function_exists('cacti_decrypt_secret'))->toBeTrue()
		->and(CACTI_SECRET_CIPHER)->toBe('aes-256-gcm')
		->and(CACTI_SECRET_TAG_LENGTH)->toBe(16);
});

it('generates, persists and then reuses a 32-byte key when none is stored', function () {
	unset($GLOBALS['__test_settings']['secret_encryption_key']);

	$key = cacti_secret_key();

	expect(strlen($key))->toBe(32)
		->and($GLOBALS['__test_settings']['secret_encryption_key'] ?? '')->not->toBe('')
		->and(cacti_secret_key())->toBe($key);
});

it('reuses an already-stored key verbatim', function () {
	$raw = str_repeat('a', 32);
	$GLOBALS['__test_settings']['secret_encryption_key'] = base64_encode($raw);

	expect(cacti_secret_key())->toBe($raw);
});

it('throws when the stored key is present but corrupt', function () {
	$GLOBALS['__test_settings']['secret_encryption_key'] = 'not-base64-or-32-bytes';

	expect(fn () => cacti_secret_key())->toThrow(RuntimeException::class);
});

it('rejects an existing but empty stored key instead of silently regenerating', function () {
	// INSERT IGNORE will not overwrite the existing (empty) row, so a blank key
	// must surface as a hard error rather than being quietly replaced.
	$GLOBALS['__test_settings']['secret_encryption_key'] = '';

	expect(fn () => cacti_secret_key())->toThrow(RuntimeException::class);
});

it('round-trips a secret through the GCM helpers with an explicit key', function () {
	$key = str_repeat('k', 32);
	$ct  = cacti_encrypt_secret_with_key('s3cr3t', $key);

	expect($ct)->not->toBe('')
		->and($ct)->not->toBe('s3cr3t')
		->and(cacti_decrypt_secret_with_key($ct, $key))->toBe('s3cr3t');
});

it('treats empty input as empty on both encrypt and decrypt', function () {
	$key = str_repeat('k', 32);

	expect(cacti_encrypt_secret_with_key('', $key))->toBe('')
		->and(cacti_decrypt_secret_with_key('', $key))->toBe('');
});

it('emits the core ciphertext format: base64 of IV + tag + ciphertext', function () {
	$key = str_repeat('k', 32);
	$raw = base64_decode(cacti_encrypt_secret_with_key('abc', $key), true);

	// 12-byte GCM IV + 16-byte tag + ciphertext (same length as plaintext for GCM)
	expect($raw)->not->toBeFalse()
		->and(strlen($raw))->toBe(12 + 16 + 3);
});

it('rejects a tampered or malformed ciphertext rather than returning plaintext', function () {
	$key = str_repeat('k', 32);
	$ct  = cacti_encrypt_secret_with_key('tamper-me', $key);
	$raw = base64_decode($ct, true);
	$raw[0] = ($raw[0] === "\x00") ? "\x01" : "\x00";

	expect(cacti_decrypt_secret_with_key(base64_encode($raw), $key))->toBeFalse()
		->and(cacti_decrypt_secret_with_key('dG9vc2hvcnQ=', $key))->toBeFalse();
});

it('round-trips through the key-managing wrappers', function () {
	$ct = cacti_encrypt_secret('wrapped');

	expect($ct)->not->toBe('wrapped')
		->and(cacti_decrypt_secret($ct))->toBe('wrapped');
});

it('decrypt wrapper returns false (not a throw) when the key is corrupt', function () {
	$GLOBALS['__test_settings']['secret_encryption_key'] = 'corrupt';

	expect(cacti_decrypt_secret('anything'))->toBeFalse();
});
