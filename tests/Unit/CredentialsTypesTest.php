<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the credential type registry in includes/arrays.php:
 * credentials_types(), credentials_type_options() and credentials_get_type().
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

it('defines the full Tier 1 through Tier 3 credential type set', function () {
	$types = credentials_types();

	// four Tier 1, five Tier 2, five Tier 3
	expect($types)->toBeArray()
		->and($types)->toHaveCount(14);

	foreach (array('snmp_community', 'snmpv3', 'userpass', 'ssh', 'bearer_token', 'api_key', 'github_pat', 'oauth2_client', 'http_basic', 'wmi', 'ipmi', 'database', 'vmware', 'tls_cert') as $code) {
		expect($types)->toHaveKey($code);
	}

	$tiers = array();

	foreach ($types as $type) {
		$tiers[$type['tier']] = ($tiers[$type['tier']] ?? 0) + 1;
	}

	expect($tiers)->toBe(array(1 => 4, 2 => 5, 3 => 5));
});

it('declares a well-formed field schema for every type', function () {
	foreach (credentials_types() as $code => $type) {
		expect($type)->toHaveKeys(array('name', 'tier', 'class', 'fields'));

		foreach ($type['fields'] as $name => $field) {
			expect($field)->toHaveKeys(array('friendly_name', 'method', 'description'));

			if ($field['method'] === 'drop_array') {
				expect($field)->toHaveKey('array');
			}
		}
	}
});

it('marks password/secret fields as secret so they are encrypted', function () {
	$types = credentials_types();

	expect($types['userpass']['fields']['password']['secret'])->toBeTrue()
		->and($types['snmpv3']['fields']['auth_passphrase']['secret'])->toBeTrue()
		->and($types['ssh']['fields']['private_key']['secret'])->toBeTrue()
		->and($types['tls_cert']['fields']['private_key']['long'])->toBeTrue()
		->and(isset($types['ssh']['fields']['username']['secret']))->toBeFalse();
});

it('returns a cached registry on repeated calls', function () {
	expect(credentials_types())->toBe(credentials_types());
});

it('builds a type option map keyed by type code', function () {
	$options = credentials_type_options();

	expect($options)->toBeArray()
		->and($options)->toHaveCount(14)
		->and($options)->toHaveKey('snmpv3')
		->and($options['snmpv3'])->toContain('SNMP v3');
});

it('resolves a known type and rejects an unknown one', function () {
	expect(credentials_get_type('bearer_token'))->toBeArray()
		->and(credentials_get_type('does_not_exist'))->toBeFalse();
});
