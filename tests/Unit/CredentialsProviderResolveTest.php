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

/* Loaded at file scope (not in beforeAll) so the provider base class is
 * available when the in-memory FakeProvider below is declared. */
require_once __DIR__ . '/../../setup.php';

/*
 * Offline coverage for the provider orchestration layer in
 * includes/providers.php and the provider-aware branch of credentials_get():
 * configuration decryption, option building, successful resolution, missing and
 * disabled providers, driver failures, per-request caching and unchanged
 * non-secret fields. An in-memory driver stands in for the network so these run
 * entirely offline.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

beforeEach(function () {
	credentials_test_reset_db_mocks();
	credentials_test_reset_drivers();
});

afterAll(function () {
	credentials_test_reset_drivers();
});

/** An in-memory provider driver used to exercise resolution without a network. */
class FakeProvider extends AbstractProvider {
	public int $resolveCalls = 0;
	public array $resolveReturn = array(true, 'resolved-secret', '');
	public array $testReturn = array(true, 'ok');

	public function type(): string {
		return 'faketest';
	}

	public function label(): string {
		return 'Fake Store';
	}

	public function description(): string {
		return 'In-memory driver for tests.';
	}

	public function referenceHint(): string {
		return 'A fake reference.';
	}

	public function configFields(): array {
		return array(
			'endpoint' => array('friendly_name' => 'Endpoint', 'method' => 'textbox', 'description' => 'd'),
			'region'   => array('friendly_name' => 'Region', 'method' => 'textbox', 'description' => 'd', 'default' => 'us'),
			'token'    => array('friendly_name' => 'Token', 'method' => 'textbox_password', 'description' => 'd', 'secret' => true),
			'token2'   => array('friendly_name' => 'Token 2', 'method' => 'textbox_password', 'description' => 'd', 'secret' => true),
		);
	}

	public function test(array $config): array {
		return $this->testReturn;
	}

	public function resolve(array $config, string $reference): array {
		$this->resolveCalls++;

		return $this->resolveReturn;
	}
}

function credentials_test_provider_row(array $overrides = array()): array {
	return array_merge(array(
		'id'           => 1,
		'name'         => 'Fake',
		'description'  => '',
		'type'         => 'faketest',
		'enabled'      => 'on',
		'properties'   => '',
		'create_date'  => 't',
		'last_updated' => 't',
	), $overrides);
}

it('decodes provider properties and tolerates empty or non-object JSON', function () {
	expect(credentials_provider_properties(array()))->toBe(array())
		->and(credentials_provider_properties(array('properties' => '')))->toBe(array())
		->and(credentials_provider_properties(array('properties' => '"scalar"')))->toBe(array())
		->and(credentials_provider_properties(array('properties' => json_encode(array('a' => 1)))))->toBe(array('a' => 1));
});

it('returns false for a missing provider', function () {
	expect(credentials_provider_get(404))->toBeFalse();
});

it('returns false for a provider of an unknown type', function () {
	credentials_test_mock_db('db_fetch_row_prepared', 'credential_providers WHERE id', credentials_test_provider_row(array('type' => 'bogus')));

	expect(credentials_provider_get(1))->toBeFalse();
});

it('decrypts secret config fields and applies non-secret defaults', function () {
	credentials_test_register_driver(new FakeProvider());

	$props = json_encode(array('endpoint' => 'https://x', 'token' => credentials_encrypt('super-token')));

	credentials_test_mock_db('db_fetch_row_prepared', 'credential_providers WHERE id', credentials_test_provider_row(array('properties' => $props)));

	$provider = credentials_provider_get(1);

	expect($provider)->toBeArray()
		->and($provider['type'])->toBe('faketest')
		->and($provider['config']['endpoint'])->toBe('https://x')
		->and($provider['config']['region'])->toBe('us')     // non-secret default applied
		->and($provider['config']['token'])->toBe('super-token') // secret decrypted
		->and($provider['config']['token2'])->toBe('');      // absent secret stays empty
});

it('builds provider options with the local default, labels and a disabled marker', function () {
	credentials_test_register_driver(new FakeProvider());

	credentials_test_mock_db('db_fetch_assoc_prepared', 'FROM credential_providers', array(
		array('id' => 1, 'name' => 'Prod', 'type' => 'faketest', 'enabled' => 'on'),
		array('id' => 2, 'name' => 'Legacy', 'type' => 'unknowntype', 'enabled' => ''),
	));

	$options = credentials_provider_options(2);

	expect($options[0])->toContain('Local')
		->and($options[1])->toContain('Prod')->toContain('Fake Store')
		->and($options[2])->toContain('Legacy')->toContain('(disabled)');
});

it('returns only the local option when no providers exist', function () {
	$options = credentials_provider_options();

	expect($options)->toHaveCount(1)
		->and($options)->toHaveKey(0);
});

it('fails closed when resolving against a missing provider', function () {
	expect(credentials_provider_resolve_reference(900, 'ref'))->toBeFalse();
});

it('fails closed when resolving against a disabled provider', function () {
	credentials_test_register_driver(new FakeProvider());
	credentials_test_mock_db('db_fetch_row_prepared', 'credential_providers WHERE id', credentials_test_provider_row(array('id' => 10, 'enabled' => '')));

	expect(credentials_provider_resolve_reference(10, 'ref'))->toBeFalse();
});

it('resolves a reference through the driver and caches the result per request', function () {
	$fake = new FakeProvider();
	$fake->resolveReturn = array(true, 'the-secret', '');
	credentials_test_register_driver($fake);
	credentials_test_mock_db('db_fetch_row_prepared', 'credential_providers WHERE id', credentials_test_provider_row(array('id' => 11)));

	expect(credentials_provider_resolve_reference(11, 'path#k'))->toBe('the-secret')
		->and(credentials_provider_resolve_reference(11, 'path#k'))->toBe('the-secret')
		->and($fake->resolveCalls)->toBe(1);
});

it('fails closed when the driver cannot resolve a reference', function () {
	$fake = new FakeProvider();
	$fake->resolveReturn = array(false, null, 'boom');
	credentials_test_register_driver($fake);
	credentials_test_mock_db('db_fetch_row_prepared', 'credential_providers WHERE id', credentials_test_provider_row(array('id' => 12)));

	expect(credentials_provider_resolve_reference(12, 'ref'))->toBeFalse();
});

it('runs a provider self-test and reports a missing provider', function () {
	$fake = new FakeProvider();
	$fake->testReturn = array(true, 'Great');
	credentials_test_register_driver($fake);

	// id-aware fixture: only provider 20 exists, so a lookup for 999 misses
	credentials_test_mock_db('db_fetch_row_prepared', 'credential_providers WHERE id', function ($sql, $params) {
		return (isset($params[0]) && (int) $params[0] === 20) ? credentials_test_provider_row(array('id' => 20)) : array();
	});

	expect(credentials_provider_test(20))->toBe(array(true, 'Great'))
		->and(credentials_provider_test(999)[0])->toBeFalse();
});

it('resolves provider-backed secret fields through credentials_get', function () {
	$fake = new FakeProvider();
	$fake->resolveReturn = array(true, 'resolved-pw', '');
	credentials_test_register_driver($fake);

	credentials_test_mock_db('db_fetch_row_prepared', 'credential_providers WHERE id', credentials_test_provider_row(array('id' => 30)));

	$props = json_encode(array('username' => 'bob', 'password' => 'kv/app#pw'));
	credentials_test_mock_db('db_fetch_row_prepared', 'FROM credentials WHERE id', array(
		'id' => 5, 'name' => 'C', 'description' => '', 'type' => 'userpass',
		'provider_id' => 30, 'user_id' => 1, 'enabled' => 'on', 'properties' => $props,
		'create_date' => 't', 'last_updated' => 't',
	));

	$credential = credentials_get(5);

	expect($credential['provider_id'])->toBe(30)
		->and($credential['fields']['username'])->toBe('bob')      // non-secret unchanged
		->and($credential['fields']['password'])->toBe('resolved-pw'); // provider resolved
});

it('decrypts local secret fields through credentials_get', function () {
	$props = json_encode(array('username' => 'ann', 'password' => credentials_encrypt('s3cret')));
	credentials_test_mock_db('db_fetch_row_prepared', 'FROM credentials WHERE id', array(
		'id' => 6, 'name' => 'L', 'description' => '', 'type' => 'userpass',
		'provider_id' => 0, 'user_id' => 1, 'enabled' => 'on', 'properties' => $props,
		'create_date' => 't', 'last_updated' => 't',
	));

	$credential = credentials_get(6);

	expect($credential['provider_id'])->toBe(0)
		->and($credential['fields']['username'])->toBe('ann')
		->and($credential['fields']['password'])->toBe('s3cret');
});

it('returns false from credentials_get for a missing credential', function () {
	expect(credentials_get(0))->toBeFalse();
});
