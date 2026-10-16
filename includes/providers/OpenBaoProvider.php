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

/**
 * OpenBao driver. OpenBao is the open-source fork of HashiCorp Vault and keeps
 * Vault's HTTP API, including the X-Vault-Token and X-Vault-Namespace headers,
 * the KV v1/v2 secrets engines and the token and AppRole auth methods. The
 * transport, authentication and reference handling are therefore inherited from
 * VaultProvider unchanged; this class only gives OpenBao its own type code and
 * wording so a provider instance is identified as OpenBao in the UI.
 */
class OpenBaoProvider extends VaultProvider {
	public function type(): string {
		return 'openbao';
	}

	public function label(): string {
		return __('OpenBao', 'credentials');
	}

	protected function product(): string {
		return 'OpenBao';
	}

	public function description(): string {
		return __('Resolve secrets from an OpenBao KV v1 or v2 secrets engine using a token or AppRole.', 'credentials');
	}

	public function referenceHint(): string {
		return __('An OpenBao secret path and the key within it, separated by \'#\', for example \'network/snmp#community\'. The path is relative to the configured KV mount; append \'#key\' to select a field from the secret.', 'credentials');
	}

	public function configFields(): array {
		$fields = parent::configFields();

		$descriptions = array(
			'address'        => array(__('OpenBao Address', 'credentials'), __('The base URL of the OpenBao server, for example https://openbao.example.com:8200.', 'credentials')),
			'namespace'      => array(null, __('The optional OpenBao namespace (sent as the X-Vault-Namespace header).', 'credentials')),
			'auth_method'    => array(null, __('How this plugin authenticates to OpenBao.', 'credentials')),
			'token'          => array(null, __('The OpenBao token used for Token authentication. Stored encrypted.', 'credentials')),
			'tls_verify'     => array(null, __('Verify the OpenBao server TLS certificate. Disable only for testing.', 'credentials')),
			'ca_bundle_path' => array(null, __('An optional path on the Cacti server to a PEM CA bundle used to verify OpenBao.', 'credentials')),
			'timeout'        => array(null, __('The network timeout for OpenBao requests.', 'credentials')),
		);

		foreach ($descriptions as $name => $text) {
			if ($text[0] !== null) {
				$fields[$name]['friendly_name'] = $text[0];
			}

			$fields[$name]['description'] = $text[1];
		}

		return $fields;
	}
}
