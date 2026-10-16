<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/* Loaded at file scope (not in beforeAll) so OpenBaoProvider is available when
 * the TestableOpenBaoProvider subclass below is declared. */
require_once __DIR__ . '/../../setup.php';

/*
 * Coverage for OpenBaoProvider: its identity and wording, and that it resolves
 * secrets through the Vault-compatible API it inherits, driven without a
 * network by stubbing the HTTP transport.
 */

/** An OpenBaoProvider whose HTTP calls return canned responses and record requests. */
class TestableOpenBaoProvider extends OpenBaoProvider {
	public array $responses = array();
	public array $urls      = array();
	public array $headers   = array();

	protected function http(array $config, string $method, string $url, array $headers = array(), ?string $body = null): array {
		$this->urls[]    = $url;
		$this->headers[] = $headers;

		return array_shift($this->responses);
	}
}

function credentials_test_openbao_config(): array {
	return array(
		'address'     => 'https://openbao.example.com:8200',
		'auth_method' => 'token',
		'token'       => 't0ken',
		'kv_version'  => '2',
		'mount'       => 'secret',
		'namespace'   => 'team-a',
	);
}

it('identifies itself as an OpenBao driver, distinct from Vault', function () {
	$driver = new OpenBaoProvider();

	expect($driver)->toBeInstanceOf(CredentialProvider::class)
		->and($driver->type())->toBe('openbao')
		->and($driver->label())->toBe('OpenBao')
		->and($driver->type())->not->toBe((new VaultProvider())->type())
		->and($driver->description())->toContain('OpenBao')
		->and($driver->referenceHint())->toContain('OpenBao');
});

it('keeps the Vault connection fields but words them for OpenBao', function () {
	$vault   = (new VaultProvider())->configFields();
	$openbao = (new OpenBaoProvider())->configFields();

	expect(array_keys($openbao))->toBe(array_keys($vault));

	foreach ($openbao as $name => $field) {
		expect($field['method'])->toBe($vault[$name]['method']);
		expect(str_replace('X-Vault-Namespace', '', $field['description']))->not->toContain('Vault');
		expect(!empty($field['secret']))->toBe(!empty($vault[$name]['secret']));
	}

	expect($openbao['address']['friendly_name'])->toContain('OpenBao')
		->and($openbao['token']['secret'])->toBeTrue()
		->and($openbao['secret_id']['secret'])->toBeTrue();
});

it('resolves a KV v2 secret and sends the token and namespace headers', function () {
	$driver            = new TestableOpenBaoProvider();
	$driver->responses = array(
		array(200, json_encode(array('data' => array('data' => array('community' => 'public', 'other' => 'x')))), ''),
	);

	list($ok, $value, $error) = $driver->resolve(credentials_test_openbao_config(), 'net/snmp#community');

	expect($ok)->toBeTrue()
		->and($value)->toBe('public')
		->and($error)->toBe('')
		->and($driver->urls[0])->toBe('https://openbao.example.com:8200/v1/secret/data/net/snmp')
		->and($driver->headers[0])->toContain('X-Vault-Token: t0ken')
		->and($driver->headers[0])->toContain('X-Vault-Namespace: team-a');
});

it('resolves a KV v1 secret', function () {
	$driver            = new TestableOpenBaoProvider();
	$driver->responses = array(
		array(200, json_encode(array('data' => array('community' => 'public'))), ''),
	);

	$config               = credentials_test_openbao_config();
	$config['kv_version'] = '1';

	list($ok, $value) = $driver->resolve($config, 'net/snmp#community');

	expect($ok)->toBeTrue()
		->and($value)->toBe('public')
		->and($driver->urls[0])->toBe('https://openbao.example.com:8200/v1/secret/net/snmp');
});

it('logs in with AppRole before reading the secret', function () {
	$driver            = new TestableOpenBaoProvider();
	$driver->responses = array(
		array(200, json_encode(array('auth' => array('client_token' => 'approle-token'))), ''),
		array(200, json_encode(array('data' => array('data' => array('pw' => 'secret')))), ''),
	);

	$config                = credentials_test_openbao_config();
	$config['auth_method'] = 'approle';
	$config['role_id']     = 'role';
	$config['secret_id']   = 'sid';

	list($ok, $value) = $driver->resolve($config, 'app/db#pw');

	expect($ok)->toBeTrue()
		->and($value)->toBe('secret')
		->and($driver->urls[0])->toBe('https://openbao.example.com:8200/v1/auth/approle/login')
		->and($driver->headers[1])->toContain('X-Vault-Token: approle-token');
});

it('reports a missing secret without leaking a value', function () {
	$driver            = new TestableOpenBaoProvider();
	$driver->responses = array(array(404, '', ''));

	list($ok, $value, $error) = $driver->resolve(credentials_test_openbao_config(), 'missing/path#key');

	expect($ok)->toBeFalse()
		->and($value)->toBeNull()
		->and($error)->toContain('OpenBao')
		->and($error)->toContain('missing/path')
		->and($error)->not->toContain('Vault');
});

it('names OpenBao, not Vault, in connection-test diagnostics', function () {
	$driver            = new TestableOpenBaoProvider();
	$driver->responses = array(array(200, '{}', ''));

	list($ok, $message) = $driver->test(credentials_test_openbao_config());

	expect($ok)->toBeTrue()
		->and($message)->toBe('Successfully authenticated to OpenBao.');

	$driver->responses = array(array(403, '', ''));

	list($ok, $message) = $driver->test(credentials_test_openbao_config());

	expect($ok)->toBeFalse()
		->and($message)->toContain('OpenBao returned HTTP 403')
		->and($message)->not->toContain('Vault');

	list($ok, $message) = $driver->test(array('address' => ''));

	expect($ok)->toBeFalse()
		->and($message)->toBe('The OpenBao address is required.');
});

it('names OpenBao, not Vault, in authentication and payload diagnostics', function () {
	$base = credentials_test_openbao_config();

	$driver = new TestableOpenBaoProvider();
	list($ok, , $error) = $driver->resolve(array_merge($base, array('token' => '')), 'a/b#k');
	expect($ok)->toBeFalse()->and($error)->toBe('The OpenBao token is required for Token authentication.');

	$approle = array_merge($base, array('auth_method' => 'approle', 'role_id' => 'r', 'secret_id' => 's'));

	$driver->responses = array(array(403, '', ''));
	list($ok, , $error) = $driver->resolve($approle, 'a/b#k');
	expect($ok)->toBeFalse()->and($error)->toBe('OpenBao AppRole login failed with HTTP 403.');

	$driver->responses = array(array(200, '{}', ''));
	list($ok, , $error) = $driver->resolve($approle, 'a/b#k');
	expect($ok)->toBeFalse()->and($error)->toBe('OpenBao AppRole login returned no client token.');

	list($ok, , $error) = $driver->resolve($base, '');
	expect($ok)->toBeFalse()->and($error)->toBe('The OpenBao secret path is required.');

	$driver->responses = array(array(500, '', ''));
	list($ok, , $error) = $driver->resolve($base, 'a/b#k');
	expect($ok)->toBeFalse()->and($error)->toBe('OpenBao returned HTTP 500 reading the secret.');

	$driver->responses = array(array(200, 'not json', ''));
	list($ok, , $error) = $driver->resolve($base, 'a/b#k');
	expect($ok)->toBeFalse()->and($error)->toBe('OpenBao returned an unexpected response reading the secret.');

	$driver->responses = array(array(200, json_encode(array('data' => array('data' => array('a' => '1', 'b' => '2')))), ''));
	list($ok, , $error) = $driver->resolve($base, 'a/b');
	expect($ok)->toBeFalse()->and($error)->toContain('The OpenBao secret holds multiple fields');
});

it('keeps Vault diagnostics naming Vault', function () {
	$driver            = new VaultProvider();
	$reflection        = new ReflectionMethod($driver, 'product');
	$reflection->setAccessible(true);

	expect($reflection->invoke($driver))->toBe('Vault');

	list($ok, $message) = $driver->test(array('address' => ''));

	expect($ok)->toBeFalse()
		->and($message)->toBe('The Vault address is required.');
});
