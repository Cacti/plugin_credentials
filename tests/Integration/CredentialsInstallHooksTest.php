<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Integration coverage for plugin_credentials_install(): verifies every hook
 * the plugin depends on is registered and its 'credentials' table is
 * provisioned, in a single end-to-end pass.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

beforeEach(function () {
	$GLOBALS['__test_registered_hooks'] = array();
	$GLOBALS['__test_db_calls']         = array();
});

it('registers every hook credentials depends on and provisions its table', function () {
	plugin_credentials_install();

	$hooks = array();

	foreach ($GLOBALS['__test_registered_hooks'] as $registered) {
		$hooks[$registered['hook']] = $registered;
	}

	foreach (array('config_arrays', 'draw_navigation_text', 'page_head') as $expected) {
		expect($hooks)->toHaveKey($expected);
		expect($hooks[$expected]['name'])->toBe('credentials');
		expect($hooks[$expected]['file'])->toBe('setup.php');
	}

	$tables = array_column(array_filter($GLOBALS['__test_db_calls'], function ($call) {
		return $call['fn'] === 'api_plugin_db_table_create';
	}), 'sql');

	expect($tables)->toContain('credentials');
});
