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
 * Unit coverage for the external secret-provider registry in
 * includes/providers.php: the six shipped drivers, their lookup helpers and
 * the option/config-field shape the UI renders from.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

beforeEach(function () {
	credentials_test_reset_drivers();
});

it('registers exactly the six shipped provider drivers', function () {
	$registry = credentials_provider_registry();

	expect($registry)->toBeArray()
		->and($registry)->toHaveCount(6);

	foreach (array('vault', 'openbao', 'aws', 'azure', 'gcp', 'conjur') as $type) {
		expect($registry)->toHaveKey($type);
		expect($registry[$type])->toBeInstanceOf(CredentialProvider::class);
	}
});

it('returns a cached registry on repeated calls', function () {
	expect(credentials_provider_registry())->toBe(credentials_provider_registry());
});

it('keys each driver by its own type code and exposes a label and description', function () {
	foreach (credentials_provider_registry() as $type => $driver) {
		expect($driver->type())->toBe($type)
			->and($driver->label())->toBeString()->not->toBe('')
			->and($driver->description())->toBeString()->not->toBe('')
			->and($driver->referenceLabel())->toBeString()->not->toBe('')
			->and($driver->referenceHint())->toBeString()->not->toBe('');
	}
});

it('declares a well-formed config field schema with at least one secret per driver', function () {
	foreach (credentials_provider_registry() as $type => $driver) {
		$fields = $driver->configFields();

		expect($fields)->toBeArray()->not->toBe(array());

		$has_secret = false;

		foreach ($fields as $name => $field) {
			expect($field)->toHaveKeys(array('friendly_name', 'method', 'description'));

			if ($field['method'] === 'drop_array') {
				expect($field)->toHaveKey('array');
			}

			if (!empty($field['secret'])) {
				$has_secret = true;
			}
		}

		expect($has_secret)->toBeTrue("driver '$type' should mark at least one field secret");
	}
});

it('resolves a known driver and rejects an unknown one', function () {
	expect(credentials_provider_driver('vault'))->toBeInstanceOf(VaultProvider::class)
		->and(credentials_provider_driver('aws'))->toBeInstanceOf(AwsSecretsManagerProvider::class)
		->and(credentials_provider_driver('does_not_exist'))->toBeNull();
});

it('builds a provider type option map keyed by type code', function () {
	$options = credentials_provider_type_options();

	expect($options)->toBeArray()
		->and($options)->toHaveCount(6)
		->and($options)->toHaveKey('vault')
		->and($options['vault'])->toContain('Vault')
		->and($options['openbao'])->toContain('OpenBao')
		->and($options)->toHaveKey('aws')
		->and($options['conjur'])->toContain('Conjur');
});

it('exposes the config field helper for a type and an empty set for an unknown type', function () {
	expect(credentials_provider_config_fields('azure'))->toHaveKey('vault_url')
		->and(credentials_provider_config_fields('nope'))->toBe(array());
});
