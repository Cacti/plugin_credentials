<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for includes/functions.php: the encryption wrappers, the
 * property decoder, the secret-presence check and credentials_get().
 *
 * The bootstrap defines reversible cacti_encrypt_secret and
 * cacti_decrypt_secret doubles, so round-trip behaviour is asserted without the
 * real per-install key while still proving secrets are never stored as clear
 * text.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

beforeEach(function () {
	credentials_test_reset_db_mocks();
	credentials_test_reset_key();
});

it('reports the core encryption facility as available under the test doubles', function () {
	expect(credentials_encryption_available())->toBeTrue();
});

it('encrypts a secret to a non-clear-text value and round-trips it', function () {
	$encrypted = credentials_encrypt('s3cr3t');

	expect($encrypted)->not->toBe('s3cr3t')
		->and($encrypted)->not->toBe('')
		->and(credentials_decrypt($encrypted))->toBe('s3cr3t');
});

it('treats an empty secret as empty on both encrypt and decrypt', function () {
	expect(credentials_encrypt(''))->toBe('')
		->and(credentials_decrypt(''))->toBe('');
});

it('decodes the JSON properties blob, tolerating missing and invalid JSON', function () {
	expect(credentials_properties(array('properties' => '')))->toBe(array())
		->and(credentials_properties(array('id' => 1)))->toBe(array())
		->and(credentials_properties(array('properties' => 'not-json')))->toBe(array())
		->and(credentials_properties(array('properties' => '{"a":"b"}')))->toBe(array('a' => 'b'));
});

it('detects whether a secret field currently holds a value', function () {
	$props = array('password' => 'x', 'blank' => '');

	expect(credentials_secret_is_set($props, 'password'))->toBeTrue()
		->and(credentials_secret_is_set($props, 'blank'))->toBeFalse()
		->and(credentials_secret_is_set($props, 'absent'))->toBeFalse();
});

it('returns false from credentials_get when the credential is missing', function () {
	credentials_test_mock_db('db_fetch_row_prepared', 'FROM credentials', array());

	expect(credentials_get(999))->toBeFalse();
});

it('returns a credential with its secret fields decrypted', function () {
	$row = array(
		'id'           => 7,
		'name'         => 'api',
		'description'  => 'test',
		'type'         => 'userpass',
		'user_id'      => 2,
		'enabled'      => 'on',
		'create_date'  => '2026-01-01 00:00:00',
		'last_updated' => '2026-01-02 00:00:00',
		'properties'   => json_encode(array('username' => 'bob', 'password' => credentials_encrypt('pw'))),
	);

	credentials_test_mock_db('db_fetch_row_prepared', 'FROM credentials', $row);

	$cred = credentials_get(7);

	expect($cred)->toBeArray()
		->and($cred['name'])->toBe('api')
		->and($cred['fields']['username'])->toBe('bob')
		->and($cred['fields']['password'])->toBe('pw');
});

it('returns empty fields for a credential whose type is unknown', function () {
	$row = array(
		'id'           => 8,
		'name'         => 'orphan',
		'description'  => '',
		'type'         => 'gone',
		'user_id'      => 0,
		'enabled'      => 'on',
		'create_date'  => '2026-01-01 00:00:00',
		'last_updated' => '2026-01-01 00:00:00',
		'properties'   => '{"foo":"bar"}',
	);

	credentials_test_mock_db('db_fetch_row_prepared', 'FROM credentials', $row);

	$cred = credentials_get(8);

	expect($cred['fields'])->toBe(array());
});
