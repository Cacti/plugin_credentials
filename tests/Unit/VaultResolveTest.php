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

/* Loaded at file scope (not in beforeAll) so VaultProvider is available when
 * the TestableVaultProvider subclass below is declared. */
require_once __DIR__ . '/../../setup.php';

/*
 * Regression coverage for VaultProvider::resolve(), driving the KV response
 * parsing without a network by stubbing the HTTP transport. Exercises the
 * dotted-path selector and the structured single-field case that previously
 * returned the literal string 'Array'.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

/** A VaultProvider whose HTTP calls return canned responses. */
class TestableVaultProvider extends VaultProvider {
	public array $responses = array();

	protected function http(array $config, string $method, string $url, array $headers = array(), ?string $body = null): array {
		return array_shift($this->responses);
	}
}

function credentials_test_vault_config(): array {
	return array(
		'address'     => 'https://vault.example.com',
		'auth_method' => 'token',
		'token'       => 't0ken',
		'kv_version'  => '2',
		'mount'       => 'secret',
	);
}

it('resolves a nested KV v2 value through a dotted-path selector', function () {
	$vault = new TestableVaultProvider();
	$vault->responses = array(
		array(200, json_encode(array('data' => array('data' => array('db' => array('creds' => array('pw' => 'deep')))))), ''),
	);

	list($ok, $value, $error) = $vault->resolve(credentials_test_vault_config(), 'app/db#db.creds.pw');

	expect($ok)->toBeTrue()
		->and($value)->toBe('deep')
		->and($error)->toBe('');
});

it('json-encodes a structured single field when no key is selected', function () {
	$vault = new TestableVaultProvider();
	$vault->responses = array(
		array(200, json_encode(array('data' => array('data' => array('block' => array('a' => 1))))), ''),
	);

	list($ok, $value) = $vault->resolve(credentials_test_vault_config(), 'app/block');

	expect($ok)->toBeTrue()
		->and(json_decode($value, true))->toBe(array('a' => 1));
});

it('returns the single scalar field when no key is selected', function () {
	$vault = new TestableVaultProvider();
	$vault->responses = array(
		array(200, json_encode(array('data' => array('data' => array('community' => 'public')))), ''),
	);

	list($ok, $value) = $vault->resolve(credentials_test_vault_config(), 'net/snmp');

	expect($ok)->toBeTrue()
		->and($value)->toBe('public');
});

it('fails when a multi-field secret is resolved without a key', function () {
	$vault = new TestableVaultProvider();
	$vault->responses = array(
		array(200, json_encode(array('data' => array('data' => array('a' => '1', 'b' => '2')))), ''),
	);

	list($ok, $value, $error) = $vault->resolve(credentials_test_vault_config(), 'app/multi');

	expect($ok)->toBeFalse()
		->and($value)->toBeNull()
		->and($error)->not->toBe('');
});

it('reports a not-found Vault secret path', function () {
	$vault = new TestableVaultProvider();
	$vault->responses = array(array(404, '', ''));

	list($ok, $value, $error) = $vault->resolve(credentials_test_vault_config(), 'missing/path#k');

	expect($ok)->toBeFalse()
		->and($value)->toBeNull()
		->and($error)->toContain('missing/path');
});
