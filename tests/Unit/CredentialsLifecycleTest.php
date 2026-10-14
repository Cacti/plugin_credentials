<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the setup.php lifecycle and hook functions:
 * plugin_credentials_install(), _uninstall(), _check_config(), _upgrade(),
 * credentials_setup_table(), credentials_config_arrays(),
 * credentials_draw_navigation_text() and credentials_page_head().
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

beforeEach(function () {
	$GLOBALS['__test_registered_hooks'] = array();
	$GLOBALS['__test_db_calls']         = array();
	$GLOBALS['__test_current_page']     = '';
	$GLOBALS['user_auth_realm_filenames'] = array();
	unset($GLOBALS['menu']);
});

it('reports a complete config and no pending upgrade', function () {
	expect(plugin_credentials_check_config())->toBeTrue()
		->and(plugin_credentials_upgrade())->toBeFalse();
});

it('performs no work on uninstall', function () {
	plugin_credentials_uninstall();

	expect($GLOBALS['__test_db_calls'])->toBe(array());
});

it('registers its hooks and creates the credentials table on install', function () {
	plugin_credentials_install();

	$hooks = array_column($GLOBALS['__test_registered_hooks'], 'hook');

	expect($hooks)->toContain('config_arrays')
		->and($hooks)->toContain('draw_navigation_text')
		->and($hooks)->toContain('page_head');

	$tables = array_column(array_filter($GLOBALS['__test_db_calls'], function ($call) {
		return $call['fn'] === 'api_plugin_db_table_create';
	}), 'sql');

	expect($tables)->toBe(array('credentials'));
});

it('gates the page on the Users/Groups realm and returns early without a menu', function () {
	credentials_config_arrays();

	expect($GLOBALS['user_auth_realm_filenames']['credentials.php'])->toBe(1);
});

it('inserts the Credentials pick directly after User Domains', function () {
	$GLOBALS['menu'] = array(
		'Broken'        => 'not-an-array',
		'Configuration' => array(
			'settings.php'     => 'Settings',
			'user_domains.php' => 'User Domains',
			'utilities.php'    => 'Utilities',
		),
	);

	credentials_config_arrays();

	$keys = array_keys($GLOBALS['menu']['Configuration']);

	$pos = array_search('user_domains.php', $keys, true);

	expect($keys[$pos + 1])->toBe('plugins/credentials/credentials.php')
		->and($GLOBALS['menu']['Configuration']['plugins/credentials/credentials.php'])->toBe('Credentials');
});

it('falls back to appending under Configuration when no anchor exists', function () {
	$GLOBALS['menu'] = array(
		'Configuration' => array(
			'settings.php' => 'Settings',
		),
	);

	credentials_config_arrays();

	expect($GLOBALS['menu']['Configuration'])->toHaveKey('plugins/credentials/credentials.php');
});

it('provides breadcrumb navigation entries for the page', function () {
	$nav = credentials_draw_navigation_text(array());

	expect($nav)->toHaveKey('credentials.php:')
		->and($nav)->toHaveKey('credentials.php:edit')
		->and($nav['credentials.php:']['url'])->toBe('credentials.php');
});

it('emits the plugin javascript only on the credentials page', function () {
	$GLOBALS['__test_current_page'] = 'credentials.php';

	ob_start();
	credentials_page_head();
	$out = ob_get_clean();

	expect($out)->toContain('plugins/credentials/credentials.js');
});

it('emits nothing on other pages', function () {
	$GLOBALS['__test_current_page'] = 'host.php';

	ob_start();
	credentials_page_head();
	$out = ob_get_clean();

	expect($out)->toBe('');
});
