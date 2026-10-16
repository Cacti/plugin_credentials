<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the shared reference parsing and JSON selection helpers in
 * AbstractProvider, which every driver relies on to split a stored reference
 * and pull a value (optionally a nested JSON key) from a store payload. The
 * protected helpers are exercised through reflection on a concrete driver.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

function credentials_provider_invoke(string $method, array $args) {
	$driver = new VaultProvider();
	$ref    = new ReflectionMethod(VaultProvider::class, $method);
	$ref->setAccessible(true);

	return $ref->invokeArgs($driver, $args);
}

it('splits a reference into locator and optional json key', function () {
	expect(credentials_provider_invoke('splitReference', array('network/snmp#community')))
		->toBe(array('network/snmp', 'community'));

	expect(credentials_provider_invoke('splitReference', array('just/a/path')))
		->toBe(array('just/a/path', null));

	// a trailing '#' selects no key
	expect(credentials_provider_invoke('splitReference', array('path#')))
		->toBe(array('path', null));

	// surrounding whitespace is trimmed from the reference and the locator; the
	// leading space of the key is preserved, the trailing one dropped with it
	expect(credentials_provider_invoke('splitReference', array('  a/b # key ')))
		->toBe(array('a/b', ' key'));
});

it('returns the raw payload when no json key is requested', function () {
	expect(credentials_provider_invoke('selectValue', array('s3cr3t', null)))
		->toBe(array(true, 's3cr3t', ''));
});

it('selects a top-level json key', function () {
	$payload = json_encode(array('password' => 'p@ss', 'user' => 'admin'));

	expect(credentials_provider_invoke('selectValue', array($payload, 'password')))
		->toBe(array(true, 'p@ss', ''));
});

it('selects a nested json key via a dotted path', function () {
	$payload = json_encode(array('db' => array('creds' => array('pw' => 'deep'))));

	expect(credentials_provider_invoke('selectValue', array($payload, 'db.creds.pw')))
		->toBe(array(true, 'deep', ''));
});

it('fails when the requested key is missing', function () {
	$payload = json_encode(array('user' => 'admin'));

	list($ok, $value, $error) = credentials_provider_invoke('selectValue', array($payload, 'password'));

	expect($ok)->toBeFalse()
		->and($value)->toBeNull()
		->and($error)->toContain('password');
});

it('fails when a key is requested but the payload is not json', function () {
	list($ok, $value, $error) = credentials_provider_invoke('selectValue', array('plain-text', 'password'));

	expect($ok)->toBeFalse()
		->and($value)->toBeNull()
		->and($error)->not->toBe('');
});

it('json-encodes a selected value that is itself a structure', function () {
	$payload = json_encode(array('block' => array('a' => 1)));

	list($ok, $value) = credentials_provider_invoke('selectValue', array($payload, 'block'));

	expect($ok)->toBeTrue()
		->and(json_decode($value, true))->toBe(array('a' => 1));
});
