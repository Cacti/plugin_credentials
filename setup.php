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

require_once(__DIR__ . '/includes/arrays.php');
require_once(__DIR__ . '/includes/functions.php');

/**
 * Return the CSP nonce attribute for inline/script tags, safely across Cacti
 * versions. Newer releases enforce a Content-Security-Policy requiring a
 * per-request nonce on scripts; older releases lack CactiSecureHeaders.
 *
 * @return string The nonce attribute when supported, otherwise empty string.
 */
function credentials_csp_nonce(): string {
	return class_exists('CactiSecureHeaders') ? CactiSecureHeaders::getNonceAttribute() : '';
}

/**
 * Read this plugin's version/author metadata from its INFO file. Invoked by
 * the Cacti plugin framework to display plugin information.
 *
 * @return array The INFO file 'info' section.
 */
function plugin_credentials_version(): array {
	global $config;

	$info = parse_ini_file($config['base_path'] . '/plugins/credentials/INFO', true);

	return isset($info['info']) && is_array($info['info']) ? $info['info'] : array();
}

/**
 * Register this plugin's hooks and create its database table. Invoked by the
 * Cacti plugin framework when the plugin is installed/enabled.
 *
 * @return void
 */
function plugin_credentials_install(): void {
	api_plugin_register_hook('credentials', 'config_arrays',        'credentials_config_arrays',        'setup.php');
	api_plugin_register_hook('credentials', 'draw_navigation_text', 'credentials_draw_navigation_text', 'setup.php');
	api_plugin_register_hook('credentials', 'page_head',            'credentials_page_head',            'setup.php');

	credentials_setup_table();
	credential_providers_setup_table();
}

/**
 * Uninstall hook. The credentials and credential_providers table ownership is
 * recorded by api_plugin_db_table_create(), so the framework drops them on
 * uninstall.
 *
 * @return void
 */
function plugin_credentials_uninstall(): void {
	// Nothing extra to do.
}

/**
 * Report whether the plugin's configuration is complete enough to enable.
 *
 * @return bool Always true.
 */
function plugin_credentials_check_config(): bool {
	return true;
}

/**
 * Apply any pending schema upgrade. Invoked by the Cacti plugin framework when
 * the installed version differs from the current version. The table helpers are
 * idempotent: they add the provider_id column and the credential_providers
 * table to an existing installation without disturbing stored credentials.
 *
 * @return bool True; the schema is reconciled on every upgrade.
 */
function plugin_credentials_upgrade(): bool {
	credentials_setup_table();
	credential_providers_setup_table();

	return true;
}

/**
 * Create the 'credentials' table used to store credential records. The secret
 * material inside the properties JSON is encrypted by credentials.php before
 * it is written; only non-secret fields are stored in clear text.
 *
 * @return void
 */
function credentials_setup_table(): void {
	$data = array('columns' => array(), 'keys' => array());

	$data['columns'][] = array('name' => 'id',           'type' => 'int(10)',      'unsigned' => true, 'NULL' => false, 'auto_increment' => true);
	$data['columns'][] = array('name' => 'name',         'type' => 'varchar(128)', 'NULL' => false, 'default' => '');
	$data['columns'][] = array('name' => 'description',  'type' => 'varchar(255)', 'NULL' => false, 'default' => '');
	$data['columns'][] = array('name' => 'type',         'type' => 'varchar(64)',  'NULL' => false, 'default' => '');
	$data['columns'][] = array('name' => 'provider_id',  'type' => 'int(10)',      'unsigned' => true, 'NULL' => false, 'default' => '0');
	$data['columns'][] = array('name' => 'user_id',      'type' => 'int(10)',      'unsigned' => true, 'NULL' => false, 'default' => '0');
	$data['columns'][] = array('name' => 'enabled',      'type' => 'varchar(3)',   'NULL' => false, 'default' => 'on');
	$data['columns'][] = array('name' => 'properties',   'type' => 'longtext',     'NULL' => false);
	$data['columns'][] = array('name' => 'create_date',  'type' => 'timestamp',    'NULL' => false, 'default' => 'CURRENT_TIMESTAMP');
	$data['columns'][] = array('name' => 'last_updated', 'type' => 'timestamp',    'NULL' => false, 'default' => 'CURRENT_TIMESTAMP', 'on_update' => 'CURRENT_TIMESTAMP');

	$data['primary'] = 'id';

	$data['keys'][] = array('name' => 'name',        'columns' => array('name'));
	$data['keys'][] = array('name' => 'type',        'columns' => array('type'));
	$data['keys'][] = array('name' => 'provider_id', 'columns' => array('provider_id'));
	$data['keys'][] = array('name' => 'user_id',     'columns' => array('user_id'));

	$data['type']    = 'InnoDB';
	$data['comment'] = 'Stored credentials managed by the Credentials plugin';

	api_plugin_db_table_create('credentials', 'credentials', $data);
}

/**
 * Create the 'credential_providers' table used to store external secret-store
 * provider instances (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault,
 * Google Cloud Secret Manager, CyberArk Conjur). The per-connection secrets
 * inside the properties JSON are encrypted by credential_providers.php before
 * they are written; only non-secret settings are stored in clear text.
 *
 * @return void
 */
function credential_providers_setup_table(): void {
	$data = array('columns' => array(), 'keys' => array());

	$data['columns'][] = array('name' => 'id',           'type' => 'int(10)',      'unsigned' => true, 'NULL' => false, 'auto_increment' => true);
	$data['columns'][] = array('name' => 'name',         'type' => 'varchar(128)', 'NULL' => false, 'default' => '');
	$data['columns'][] = array('name' => 'description',  'type' => 'varchar(255)', 'NULL' => false, 'default' => '');
	$data['columns'][] = array('name' => 'type',         'type' => 'varchar(32)',  'NULL' => false, 'default' => '');
	$data['columns'][] = array('name' => 'enabled',      'type' => 'varchar(3)',   'NULL' => false, 'default' => 'on');
	$data['columns'][] = array('name' => 'properties',   'type' => 'longtext',     'NULL' => false);
	$data['columns'][] = array('name' => 'create_date',  'type' => 'timestamp',    'NULL' => false, 'default' => 'CURRENT_TIMESTAMP');
	$data['columns'][] = array('name' => 'last_updated', 'type' => 'timestamp',    'NULL' => false, 'default' => 'CURRENT_TIMESTAMP', 'on_update' => 'CURRENT_TIMESTAMP');

	$data['primary'] = 'id';

	$data['keys'][] = array('name' => 'name', 'columns' => array('name'));
	$data['keys'][] = array('name' => 'type', 'columns' => array('type'));

	$data['type']    = 'InnoDB';
	$data['comment'] = 'External secret-store providers managed by the Credentials plugin';

	api_plugin_db_table_create('credentials', 'credential_providers', $data);
}

/**
 * config_arrays hook: gate credentials.php on the core Users/Groups realm and
 * place the 'Credentials' Console pick directly below 'User Domains' (Cacti
 * 1.2.x) or 'Login Providers' (develop / 1.3+).
 *
 * @return void
 */
function credentials_config_arrays(): void {
	global $menu, $user_auth_realm_filenames;

	// Realm 1 is the core 'Users/Groups' permission; mapping the page to it
	// makes include/auth.php enforce that permission for both page access and
	// Console menu visibility.
	$user_auth_realm_filenames['credentials.php'] = 1;
	$user_auth_realm_filenames['credential_providers.php'] = 1;

	if (!isset($menu) || !is_array($menu)) {
		return;
	}

	$anchors = array('user_domains.php', 'login_providers.php');

	foreach ($menu as $section => $items) {
		if (!is_array($items)) {
			continue;
		}

		$rebuilt  = array();
		$inserted = false;

		foreach ($items as $url => $title) {
			$rebuilt[$url] = $title;

			if (!$inserted && in_array($url, $anchors, true)) {
				$rebuilt['plugins/credentials/credentials.php']           = __('Credentials', 'credentials');
				$rebuilt['plugins/credentials/credential_providers.php']  = __('Secret Providers', 'credentials');
				$inserted = true;
			}
		}

		if ($inserted) {
			$menu[$section] = $rebuilt;

			return;
		}
	}

	// No known anchor present: append to the Configuration section so the picks
	// remain reachable.
	$config_section = __('Configuration');

	if (isset($menu[$config_section]) && is_array($menu[$config_section])) {
		$menu[$config_section]['plugins/credentials/credentials.php']          = __('Credentials', 'credentials');
		$menu[$config_section]['plugins/credentials/credential_providers.php'] = __('Secret Providers', 'credentials');
	}
}

/**
 * draw_navigation_text hook: breadcrumb entries for the Credentials pages.
 *
 * @param array $nav The running navigation map.
 *
 * @return array The navigation map with this plugin's entries added.
 */
function credentials_draw_navigation_text(array $nav): array {
	$nav['credentials.php:'] = array(
		'title'   => __('Credentials', 'credentials'),
		'mapping' => 'index.php:',
		'url'     => 'credentials.php',
		'level'   => 1,
	);

	$nav['credentials.php:edit'] = array(
		'title'   => __('(Edit)', 'credentials'),
		'mapping' => 'index.php:,credentials.php:',
		'url'     => '',
		'level'   => 2,
	);

	$nav['credentials.php:actions'] = array(
		'title'   => __('Actions', 'credentials'),
		'mapping' => 'index.php:,credentials.php:',
		'url'     => '',
		'level'   => 2,
	);

	$nav['credentials.php:save'] = array(
		'title'   => __('(Save)', 'credentials'),
		'mapping' => 'index.php:,credentials.php:',
		'url'     => '',
		'level'   => 2,
	);

	$nav['credential_providers.php:'] = array(
		'title'   => __('Secret Providers', 'credentials'),
		'mapping' => 'index.php:',
		'url'     => 'credential_providers.php',
		'level'   => 1,
	);

	$nav['credential_providers.php:edit'] = array(
		'title'   => __('(Edit)', 'credentials'),
		'mapping' => 'index.php:,credential_providers.php:',
		'url'     => '',
		'level'   => 2,
	);

	$nav['credential_providers.php:actions'] = array(
		'title'   => __('Actions', 'credentials'),
		'mapping' => 'index.php:,credential_providers.php:',
		'url'     => '',
		'level'   => 2,
	);

	$nav['credential_providers.php:save'] = array(
		'title'   => __('(Save)', 'credentials'),
		'mapping' => 'index.php:,credential_providers.php:',
		'url'     => '',
		'level'   => 2,
	);

	return $nav;
}

/**
 * page_head hook: load the plugin's JavaScript on its own pages only.
 *
 * @return void
 */
function credentials_page_head(): void {
	global $config;

	$page = basename(get_current_page());

	if ($page == 'credentials.php' || $page == 'credential_providers.php') {
		print '<script type=\'text/javascript\' src=\'' . $config['url_path'] . 'plugins/credentials/credentials.js\' ' . credentials_csp_nonce() . '></script>' . PHP_EOL;
	}
}
