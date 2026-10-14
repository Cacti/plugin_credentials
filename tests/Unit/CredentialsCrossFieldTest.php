<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the cross-field validator and the fail-safe encryptor in
 * includes/functions.php.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

beforeEach(function () {
	credentials_test_reset_key();
});

it('requires the SSH secret matching the chosen auth method', function () {
	expect(credentials_cross_field_error('ssh', array('auth_method' => 'password')))
		->toContain('password is required')
		->and(credentials_cross_field_error('ssh', array('auth_method' => 'key')))
		->toContain('private key is required')
		->and(credentials_cross_field_error('ssh', array('auth_method' => 'password', 'password' => 'enc')))
		->toBe('')
		->and(credentials_cross_field_error('ssh', array('auth_method' => 'key', 'private_key' => 'enc')))
		->toBe('');
});

it('rejects the SNMP v3 noAuthPriv combination', function () {
	expect(credentials_cross_field_error('snmpv3', array('auth_protocol' => 'none', 'priv_protocol' => 'AES-128')))
		->toContain('noAuthPriv');
});

it('requires SNMP v3 passphrases for each selected protocol', function () {
	expect(credentials_cross_field_error('snmpv3', array('auth_protocol' => 'SHA')))
		->toContain('authentication passphrase is required')
		->and(credentials_cross_field_error('snmpv3', array('auth_protocol' => 'SHA', 'auth_passphrase' => 'enc', 'priv_protocol' => 'AES-128')))
		->toContain('privacy passphrase is required');
});

it('accepts a fully specified SNMP v3 credential and unrelated types', function () {
	expect(credentials_cross_field_error('snmpv3', array(
		'auth_protocol'   => 'SHA',
		'auth_passphrase' => 'enc',
		'priv_protocol'   => 'AES-128',
		'priv_passphrase' => 'enc',
	)))->toBe('')
		->and(credentials_cross_field_error('userpass', array()))->toBe('');
});

it('returns a success pair when encryption works', function () {
	list($ok, $value) = credentials_try_encrypt('secret');

	expect($ok)->toBeTrue()
		->and($value)->not->toBe('')
		->and($value)->not->toBe('secret');
});

it('returns a failure pair instead of throwing when encryption fails', function () {
	$restore = $GLOBALS['__test_settings']['secret_encryption_key'];
	// a corrupt key makes cacti_secret_key() throw; credentials_try_encrypt must catch it
	$GLOBALS['__test_settings']['secret_encryption_key'] = 'not-a-valid-32-byte-key';

	try {
		list($ok, $value) = credentials_try_encrypt('secret');

		expect($ok)->toBeFalse()
			->and($value)->toBe('');
	} finally {
		$GLOBALS['__test_settings']['secret_encryption_key'] = $restore;
	}
});
