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
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 */

$source   = plugin_test_read_source('setup.php');
$infoFile = parse_ini_file(__DIR__ . '/../../INFO', true);

if (!is_array($infoFile) || !isset($infoFile['info']) || !is_array($infoFile['info'])) {
	throw new RuntimeException('Unable to parse the INFO section');
}

$info = $infoFile['info'];

it('defines plugin_credentials_install function', function () use ($source) {
	expect($source)->toContain('function plugin_credentials_install');
});

it('defines plugin_credentials_version function', function () use ($source) {
	expect($source)->toContain('function plugin_credentials_version');
});

it('defines plugin_credentials_uninstall function', function () use ($source) {
	expect($source)->toContain('function plugin_credentials_uninstall');
});

it('gates credentials.php on the core Users/Groups realm (realm 1)', function () use ($source) {
	expect($source)->toContain("\$user_auth_realm_filenames['credentials.php'] = 1;");
});

it('anchors the menu below User Domains and Login Providers', function () use ($source) {
	expect($source)->toContain('user_domains.php')
		->and($source)->toContain('login_providers.php');
});

it('declares a plugin name in INFO', function () use ($info) {
	expect($info)->toHaveKey('name');
});

it('declares a plugin version in INFO', function () use ($info) {
	expect($info)->toHaveKey('version');
});
