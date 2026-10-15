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

require_once(__DIR__ . '/providers/CredentialProvider.php');
require_once(__DIR__ . '/providers/AbstractProvider.php');
require_once(__DIR__ . '/providers/VaultProvider.php');
require_once(__DIR__ . '/providers/AwsSecretsManagerProvider.php');
require_once(__DIR__ . '/providers/AzureKeyVaultProvider.php');
require_once(__DIR__ . '/providers/GcpSecretManagerProvider.php');
require_once(__DIR__ . '/providers/ConjurProvider.php');

/**
 * The secret-store drivers this plugin ships with, keyed by stable type code.
 * Each is a stateless strategy; a provider instance (a credential_providers
 * row) supplies the per-connection configuration at call time. New third-party
 * stores are added by implementing CredentialProvider and registering here -
 * nothing else in the storage or UI layer needs to change.
 *
 * @return array<string,CredentialProvider> The driver registry.
 */
function credentials_provider_registry(): array {
	if (!isset($GLOBALS['__credentials_provider_registry'])) {
		$drivers = array(
			new VaultProvider(),
			new AwsSecretsManagerProvider(),
			new AzureKeyVaultProvider(),
			new GcpSecretManagerProvider(),
			new ConjurProvider(),
		);

		/* The unit suite may register an in-memory driver through this global so
		 * the resolution/orchestration paths can be exercised without a network.
		 * It is never populated in production. */
		if (isset($GLOBALS['__credentials_test_drivers']) && is_array($GLOBALS['__credentials_test_drivers'])) {
			$drivers = array_merge($drivers, $GLOBALS['__credentials_test_drivers']);
		}

		$registry = array();

		foreach ($drivers as $driver) {
			$registry[$driver->type()] = $driver;
		}

		$GLOBALS['__credentials_provider_registry'] = $registry;
	}

	return $GLOBALS['__credentials_provider_registry'];
}

/**
 * Fetch a single driver by type code.
 *
 * @param string $type The driver type code.
 *
 * @return CredentialProvider|null The driver, or null when the type is unknown.
 */
function credentials_provider_driver(string $type): ?CredentialProvider {
	$registry = credentials_provider_registry();

	return isset($registry[$type]) ? $registry[$type] : null;
}

/**
 * The provider type option map (type code => driver label) for the provider
 * edit form's type selector.
 *
 * @return array<string,string>
 */
function credentials_provider_type_options(): array {
	$options = array();

	foreach (credentials_provider_registry() as $type => $driver) {
		$options[$type] = $driver->label();
	}

	return $options;
}

/**
 * The configuration field definitions for a provider type.
 *
 * @param string $type The driver type code.
 *
 * @return array The config field map, or an empty array for an unknown type.
 */
function credentials_provider_config_fields(string $type): array {
	$driver = credentials_provider_driver($type);

	return $driver !== null ? $driver->configFields() : array();
}

/**
 * Decode the JSON properties blob of a provider row.
 *
 * @param array $provider A credential_providers table row.
 *
 * @return array The decoded property map, or an empty array.
 */
function credentials_provider_properties(array $provider): array {
	if (!isset($provider['properties']) || $provider['properties'] === '') {
		return array();
	}

	$props = json_decode($provider['properties'], true);

	return is_array($props) ? $props : array();
}

/**
 * Fetch a provider instance and return its row together with a decrypted
 * configuration map. Secret config fields (tokens, keys, client secrets) are
 * decrypted with the Cacti core secret functions; non-secret fields pass
 * through unchanged.
 *
 * @param int $id The provider id.
 *
 * @return array|false The provider meta plus a decrypted 'config' map, or false
 *                     when the provider does not exist or its type is unknown.
 */
function credentials_provider_get(int $id): array|false {
	$provider = db_fetch_row_prepared('SELECT * FROM credential_providers WHERE id = ?', array($id));

	if (!is_array($provider) || cacti_sizeof($provider) == 0) {
		return false;
	}

	$driver = credentials_provider_driver($provider['type']);

	if ($driver === null) {
		return false;
	}

	$props  = credentials_provider_properties($provider);
	$fields = $driver->configFields();
	$config = array();

	foreach ($fields as $name => $def) {
		$value = isset($props[$name]) ? $props[$name] : (isset($def['default']) ? $def['default'] : '');

		if (!empty($def['secret']) && $value !== '') {
			$decrypted = credentials_decrypt($value);
			$value     = ($decrypted === false) ? '' : $decrypted;
		}

		$config[$name] = $value;
	}

	return array(
		'id'           => (int) $provider['id'],
		'name'         => $provider['name'],
		'description'  => $provider['description'],
		'type'         => $provider['type'],
		'enabled'      => $provider['enabled'],
		'create_date'  => $provider['create_date'],
		'last_updated' => $provider['last_updated'],
		'config'       => $config,
	);
}

/**
 * Build the Secret Provider option map for the credential edit form: the local
 * encrypted database (id 0) followed by every enabled provider instance,
 * labelled with its driver type for disambiguation.
 *
 * @param int $include_disabled_id A disabled provider id to include anyway (so
 *                                 an existing credential keeps showing its
 *                                 provider even after it is disabled); 0 for none.
 *
 * @return array<int,string> The id => label option map.
 */
function credentials_provider_options(int $include_disabled_id = 0): array {
	$options = array(0 => __('Local Database (encrypted)', 'credentials'));

	$labels = credentials_provider_type_options();

	$rows = db_fetch_assoc_prepared('SELECT id, name, type, enabled FROM credential_providers
		WHERE enabled = \'on\' OR id = ?
		ORDER BY name', array($include_disabled_id));

	if (cacti_sizeof($rows)) {
		foreach ($rows as $row) {
			$type_label = isset($labels[$row['type']]) ? $labels[$row['type']] : $row['type'];
			$suffix     = ($row['enabled'] == 'on') ? '' : ' ' . __('(disabled)', 'credentials');

			$options[(int) $row['id']] = $row['name'] . ' [' . $type_label . ']' . $suffix;
		}
	}

	return $options;
}

/**
 * Resolve a credential field reference through its provider instance to the
 * plaintext secret. Results are cached per polling cycle so a credential whose
 * fields share a provider does not trigger repeated network round trips; the
 * cache holds no value on disk, only in process memory.
 *
 * The cache is keyed per process. Long-lived consumers (the poller and
 * script-server) must call credentials_provider_flush_cache() once per polling
 * cycle so a rotated, recovered or newly disabled provider is re-evaluated
 * rather than returning a cached value for the life of the process.
 *
 * @param int    $provider_id The provider instance id.
 * @param string $reference   The field's stored reference.
 *
 * @return string|false The plaintext secret, or false when it cannot be resolved.
 */
function credentials_provider_resolve_reference(int $provider_id, string $reference): string|false {
	$GLOBALS['__credentials_resolve_cache'] = $GLOBALS['__credentials_resolve_cache'] ?? array();

	$cache     = &$GLOBALS['__credentials_resolve_cache'];
	$cache_key = $provider_id . '|' . $reference;

	if (array_key_exists($cache_key, $cache)) {
		return $cache[$cache_key];
	}

	$provider = credentials_provider_get($provider_id);

	if ($provider === false) {
		cacti_log('ERROR: CREDENTIALS - provider id ' . $provider_id . ' is missing or has an unknown type.', false, 'CREDENTIALS');

		return $cache[$cache_key] = false;
	}

	if ($provider['enabled'] != 'on') {
		cacti_log('ERROR: CREDENTIALS - provider \'' . $provider['name'] . '\' is disabled; refusing to resolve its secrets.', false, 'CREDENTIALS');

		return $cache[$cache_key] = false;
	}

	/* credentials_provider_get() has already validated the driver type */
	$driver = credentials_provider_driver($provider['type']);

	list($ok, $value, $error) = $driver->resolve($provider['config'], $reference);

	if (!$ok || $value === null) {
		/* $error is a fixed, non-sensitive diagnostic produced by the driver */
		cacti_log('ERROR: CREDENTIALS - provider \'' . $provider['name'] . '\' failed to resolve a reference: ' . $error, false, 'CREDENTIALS');

		return $cache[$cache_key] = false;
	}

	return $cache[$cache_key] = (string) $value;
}

/**
 * Flush the per-process credential resolution cache. Long-lived consumers (the
 * poller and script-server) should call this once per polling cycle so a
 * rotated secret, a recovered provider or a newly disabled provider is picked
 * up instead of a value cached for the life of the process.
 *
 * @return void
 */
function credentials_provider_flush_cache(): void {
	$GLOBALS['__credentials_resolve_cache'] = array();
}

/**
 * Run a provider instance's connectivity/auth self-test.
 *
 * @param int $id The provider id.
 *
 * @return array A [bool ok, string message] pair.
 */
function credentials_provider_test(int $id): array {
	$provider = credentials_provider_get($id);

	if ($provider === false) {
		return array(false, __('The provider could not be found or its type is unknown.', 'credentials'));
	}

	/* credentials_provider_get() has already validated the driver type */
	$driver = credentials_provider_driver($provider['type']);

	list($ok, $message) = $driver->test($provider['config']);

	return array((bool) $ok, (string) $message);
}
