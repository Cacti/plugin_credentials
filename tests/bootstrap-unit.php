<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*
 * Test bootstrap.
 *
 * The credentials plugin's sources expect to be included by Cacti, which has
 * already defined the db_*, request-variable, encryption and logging helpers
 * as plain global functions. Nothing here talks to a database or a network:
 * each Cacti function is declared as a stub that records the call in
 * $GLOBALS['__test_db_calls'] and hands back a safe default. The encryption
 * stubs are reversible so round-trip behaviour can be asserted without the
 * real per-installation key.
 *
 * The CI workflow checks out a pinned Cacti release next to this plugin so
 * Pest runs against Cacti's own Composer-managed vendor tree.
 */

$cacti_root = dirname(__DIR__, 3);
$autoload   = $cacti_root . '/include/vendor/autoload.php';
$version    = $cacti_root . '/include/cacti_version';
$expected   = __DIR__ . '/.cacti-version';

if (!is_readable($autoload)) {
	throw new RuntimeException("Cacti Composer autoloader is not readable: $autoload");
}

if (!is_readable($version)) {
	throw new RuntimeException("Cacti version file is not readable: $version");
}

if (!is_readable($expected)) {
	throw new RuntimeException("Expected Cacti version file is not readable: $expected");
}

$cacti_version    = trim((string) file_get_contents($version));
$expected_version = trim((string) file_get_contents($expected));

if ($cacti_version === '') {
	throw new RuntimeException("Cacti version file is empty: $version");
}

if ($expected_version === '') {
	throw new RuntimeException("Expected Cacti version file is empty: $expected");
}

// The CI workflow tracks a moving branch (1.2.x or develop) rather than a pinned release, so any actual version is accepted.
if (!in_array($expected_version, array('1.2.x', 'develop'), true) && $cacti_version !== $expected_version) {
	throw new RuntimeException("Expected Cacti $expected_version, found $cacti_version in $version");
}

require_once $autoload;

$GLOBALS['config'] = array(
	'base_path'       => $cacti_root,
	'url_path'        => '/cacti/',
	'cacti_version'   => $cacti_version,
	'cacti_server_os' => 'unix',
);

$GLOBALS['__test_db_calls']     = array();
$GLOBALS['__test_db_fixtures']  = array();
$GLOBALS['__test_current_page'] = '';

// Settings store backing read_config_option(); seeded with a valid 32-byte
// per-installation key so the encryption polyfill in includes/functions.php has
// a key to use. Tests may override 'secret_encryption_key' to exercise the
// empty and corrupt paths of cacti_secret_key().
$GLOBALS['__test_settings'] = array('secret_encryption_key' => base64_encode(str_repeat('k', 32)));

if (!function_exists('credentials_test_reset_key')) {
	function credentials_test_reset_key() {
		$GLOBALS['__test_settings']['secret_encryption_key'] = base64_encode(str_repeat('k', 32));
	}
}

if (!function_exists('credentials_test_mock_db')) {
	function credentials_test_mock_db($fn, $match, $result) {
		$GLOBALS['__test_db_fixtures'][] = array('fn' => $fn, 'match' => $match, 'result' => $result);
	}
}

if (!function_exists('credentials_test_reset_db_mocks')) {
	function credentials_test_reset_db_mocks() {
		$GLOBALS['__test_db_fixtures'] = array();
	}
}

if (!function_exists('credentials_test_register_driver')) {
	// Register an in-memory provider driver for the resolution/orchestration
	// tests and drop the cached registry so it is rebuilt including the driver.
	function credentials_test_register_driver($driver) {
		$GLOBALS['__credentials_test_drivers'][] = $driver;
		unset($GLOBALS['__credentials_provider_registry']);
	}
}

if (!function_exists('credentials_test_reset_drivers')) {
	// Remove any registered test drivers and the cached registry so the suite
	// returns to exactly the six production drivers.
	function credentials_test_reset_drivers() {
		unset($GLOBALS['__credentials_test_drivers'], $GLOBALS['__credentials_provider_registry']);
	}
}

if (!function_exists('credentials_test_db_result')) {
	function credentials_test_db_result($fn, $sql, $params, $default) {
		foreach (array_reverse($GLOBALS['__test_db_fixtures']) as $fixture) {
			if ($fixture['fn'] !== $fn) {
				continue;
			}

			$match = $fixture['match'];

			if (is_callable($match)) {
				if (!$match($sql, $params)) {
					continue;
				}
			} elseif (strpos($sql, $match) === false) {
				continue;
			}

			$result = $fixture['result'];

			return is_callable($result) ? $result($sql, $params) : $result;
		}

		return $default;
	}
}

if (!function_exists('db_execute')) {
	function db_execute($sql) {
		$GLOBALS['__test_db_calls'][] = array('fn' => 'db_execute', 'sql' => $sql, 'params' => array());

		return true;
	}
}

if (!function_exists('db_execute_prepared')) {
	function db_execute_prepared($sql, $params = array()) {
		$GLOBALS['__test_db_calls'][] = array('fn' => 'db_execute_prepared', 'sql' => $sql, 'params' => $params);

		// Emulate INSERT IGNORE INTO settings so cacti_secret_key() can persist a
		// freshly generated key. MySQL/MariaDB INSERT IGNORE only writes when the
		// unique `name` row is ABSENT; an existing row - even one holding an empty
		// string - is left unchanged, so model insertion for absent rows only.
		if (stripos($sql, 'INTO settings') !== false && isset($params[0], $params[1])) {
			if (!array_key_exists($params[0], $GLOBALS['__test_settings'])) {
				$GLOBALS['__test_settings'][$params[0]] = $params[1];
			}
		}

		return true;
	}
}

if (!function_exists('db_fetch_assoc')) {
	function db_fetch_assoc($sql) {
		return credentials_test_db_result('db_fetch_assoc', $sql, array(), array());
	}
}

if (!function_exists('db_fetch_assoc_prepared')) {
	function db_fetch_assoc_prepared($sql, $params = array()) {
		return credentials_test_db_result('db_fetch_assoc_prepared', $sql, $params, array());
	}
}

if (!function_exists('db_fetch_row')) {
	function db_fetch_row($sql) {
		return credentials_test_db_result('db_fetch_row', $sql, array(), array());
	}
}

if (!function_exists('db_fetch_row_prepared')) {
	function db_fetch_row_prepared($sql, $params = array()) {
		return credentials_test_db_result('db_fetch_row_prepared', $sql, $params, array());
	}
}

if (!function_exists('db_fetch_cell')) {
	function db_fetch_cell($sql) {
		return credentials_test_db_result('db_fetch_cell', $sql, array(), '');
	}
}

if (!function_exists('db_fetch_cell_prepared')) {
	function db_fetch_cell_prepared($sql, $params = array()) {
		return credentials_test_db_result('db_fetch_cell_prepared', $sql, $params, '');
	}
}

if (!function_exists('api_plugin_db_table_create')) {
	function api_plugin_db_table_create($plugin, $table, $data) {
		$GLOBALS['__test_db_calls'][] = array('fn' => 'api_plugin_db_table_create', 'sql' => $table, 'params' => $data);

		return true;
	}
}

if (!function_exists('api_plugin_db_add_column')) {
	function api_plugin_db_add_column($plugin, $table, $column) {
		$GLOBALS['__test_db_calls'][] = array('fn' => 'api_plugin_db_add_column', 'sql' => $table, 'params' => $column);

		return true;
	}
}

if (!function_exists('db_index_exists')) {
	function db_index_exists($table, $index, $log = true, $db_conn = false) {
		// Default false so the guarded index migration runs; tests may override.
		return credentials_test_db_result('db_index_exists', $table . ' ' . $index, array(), false);
	}
}

$GLOBALS['__test_registered_hooks'] = array();

if (!function_exists('api_plugin_register_hook')) {
	function api_plugin_register_hook($plugin, $hook, $function, $file, $subtype = '') {
		$GLOBALS['__test_registered_hooks'][] = array(
			'name'     => $plugin,
			'hook'     => $hook,
			'function' => $function,
			'file'     => $file,
		);

		return true;
	}
}

$GLOBALS['__test_registered_realms'] = array();

if (!function_exists('api_plugin_register_realm')) {
	function api_plugin_register_realm($plugin, $file, $description, $enabled) {
		$GLOBALS['__test_registered_realms'][] = array(
			'name'        => $plugin,
			'file'        => $file,
			'description' => $description,
			'enabled'     => $enabled,
		);

		return true;
	}
}

if (!function_exists('read_config_option')) {
	function read_config_option($name, $force = false) {
		return isset($GLOBALS['__test_settings'][$name]) ? $GLOBALS['__test_settings'][$name] : '';
	}
}

if (!function_exists('get_current_page')) {
	function get_current_page() {
		return $GLOBALS['__test_current_page'];
	}
}

if (!function_exists('html_escape')) {
	function html_escape($string) {
		return htmlspecialchars((string) $string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
	}
}

if (!function_exists('__')) {
	// Mirror Cacti core: the trailing text-domain stays in the argument list;
	// sprintf ignores extra arguments but still raises on too few, so a malformed
	// multi-placeholder i18n call surfaces as an ArgumentCountError in tests.
	function __($text, ...$args) {
		return $args === array() ? $text : vsprintf($text, $args);
	}
}

if (!function_exists('__esc')) {
	function __esc($text, ...$args) {
		return htmlspecialchars(__($text, ...$args), ENT_QUOTES | ENT_HTML5, 'UTF-8');
	}
}

if (!function_exists('cacti_log')) {
	function cacti_log($message, $also_print = false, $log_type = '', $level = 0) {
		$GLOBALS['__test_cacti_log'][] = (string) $message;
	}
}

if (!function_exists('cacti_sizeof')) {
	function cacti_sizeof($array) {
		return is_array($array) ? count($array) : 0;
	}
}

if (!function_exists('is_realm_allowed')) {
	function is_realm_allowed($realm) {
		return true;
	}
}

if (!function_exists('raise_message')) {
	function raise_message($id, $text = '', $level = 0) {
	}
}

/*
 * Activate the plugin's pre-1.2.32 encryption polyfill in the unit process so
 * includes/functions.php defines the REAL core secret helpers (not doubles).
 * With CACTI_VERSION below 1.2.32 and the settings-backed read_config_option /
 * db_execute_prepared above, the fallback implementation is genuinely exercised.
 */
if (!defined('CACTI_VERSION')) {
	define('CACTI_VERSION', '1.2.29');
}

if (!function_exists('cacti_version_compare')) {
	function cacti_version_compare($a, $b, $op) {
		return version_compare((string) $a, (string) $b, $op);
	}
}

if (!defined('MESSAGE_LEVEL_ERROR')) {
	define('MESSAGE_LEVEL_ERROR', 1);
}

if (!defined('MESSAGE_LEVEL_INFO')) {
	define('MESSAGE_LEVEL_INFO', 3);
}

if (!function_exists('plugin_test_read_source')) {
	function plugin_test_read_source($relative_file) {
		$path = realpath(__DIR__ . '/../' . $relative_file);

		if ($path === false) {
			throw new RuntimeException("Unable to resolve required file: {$relative_file}");
		}

		$contents = file_get_contents($path);

		if ($contents === false) {
			throw new RuntimeException("Unable to read required file: {$relative_file}");
		}

		return $contents;
	}
}
