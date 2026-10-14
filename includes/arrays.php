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
 * Registry of the credential types this plugin supports, grouped Tier 1
 * through Tier 3. Each type declares its own field set; the credentials.php
 * edit form is rendered from this definition and the per-field values are
 * stored as JSON in the credentials.properties column. Fields flagged
 * 'secret' are encrypted with the Cacti core secret functions before storage
 * and are never echoed back to the browser in clear text.
 *
 * Field attributes:
 *   friendly_name  - label shown on the form
 *   method         - Cacti form method: textbox|textbox_password|textarea|drop_array
 *   description    - tooltip/help text rendered beside the field
 *   required       - whether the field must be supplied
 *   secret         - encrypt the value and mask it on the form
 *   long           - render a secret as a textarea (keys/certs) instead of a box
 *   array          - option map for a drop_array
 *   default        - default value for a new credential
 *   max_length     - maximum input length for text boxes
 *
 * @return array The credential type registry keyed by stable type code.
 */
function credentials_types(): array {
	static $types = null;

	if ($types !== null) {
		return $types;
	}

	$types = array(
		/* ---------------- Tier 1: Core polling ---------------- */
		'snmp_community' => array(
			'name'   => __('SNMP v1/v2c Community', 'credentials'),
			'tier'   => 1,
			'class'  => __('SNMP', 'credentials'),
			'fields' => array(
				'snmp_version' => array(
					'friendly_name' => __('SNMP Version', 'credentials'),
					'method'        => 'drop_array',
					'description'   => __('The community-based SNMP protocol version this credential is used with.', 'credentials'),
					'array'         => array('1' => __('Version 1', 'credentials'), '2' => __('Version 2', 'credentials')),
					'default'       => '2',
					'required'      => true,
				),
				'community' => array(
					'friendly_name' => __('Read Community', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The SNMP read community string. Treated as a secret and stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 255,
				),
				'write_community' => array(
					'friendly_name' => __('Write Community', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The optional SNMP write community string. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => false,
					'max_length'    => 255,
				),
			),
		),
		'snmpv3' => array(
			'name'   => __('SNMP v3 (USM)', 'credentials'),
			'tier'   => 1,
			'class'  => __('SNMP', 'credentials'),
			'fields' => array(
				'sec_name' => array(
					'friendly_name' => __('Security Name', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The SNMP v3 USM security (user) name.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'auth_protocol' => array(
					'friendly_name' => __('Authentication Protocol', 'credentials'),
					'method'        => 'drop_array',
					'description'   => __('The USM authentication protocol. Choose [None] for noAuthNoPriv.', 'credentials'),
					'array'         => array(
						'none'    => __('None', 'credentials'),
						'MD5'     => 'MD5',
						'SHA'     => 'SHA',
						'SHA-224' => 'SHA-224',
						'SHA-256' => 'SHA-256',
						'SHA-384' => 'SHA-384',
						'SHA-512' => 'SHA-512',
					),
					'default'       => 'SHA',
				),
				'auth_passphrase' => array(
					'friendly_name' => __('Authentication Passphrase', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The USM authentication passphrase. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'max_length'    => 255,
				),
				'priv_protocol' => array(
					'friendly_name' => __('Privacy Protocol', 'credentials'),
					'method'        => 'drop_array',
					'description'   => __('The USM privacy (encryption) protocol. Choose [None] for authNoPriv.', 'credentials'),
					'array'         => array(
						'none'    => __('None', 'credentials'),
						'DES'     => 'DES',
						'AES-128' => 'AES-128',
						'AES-192' => 'AES-192',
						'AES-256' => 'AES-256',
					),
					'default'       => 'AES-128',
				),
				'priv_passphrase' => array(
					'friendly_name' => __('Privacy Passphrase', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The USM privacy passphrase. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'max_length'    => 255,
				),
				'context' => array(
					'friendly_name' => __('Context Name', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The optional SNMP v3 context name.', 'credentials'),
					'required'      => false,
					'max_length'    => 255,
				),
				'engine_id' => array(
					'friendly_name' => __('Engine ID', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The optional SNMP v3 context engine id.', 'credentials'),
					'required'      => false,
					'max_length'    => 255,
				),
			),
		),
		'userpass' => array(
			'name'   => __('Username / Password', 'credentials'),
			'tier'   => 1,
			'class'  => __('Generic', 'credentials'),
			'fields' => array(
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('A reusable username for HTTP Basic, Telnet, web UI logins or script inputs.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'password' => array(
					'friendly_name' => __('Password', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The password paired with the username. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 255,
				),
			),
		),
		'ssh' => array(
			'name'   => __('SSH', 'credentials'),
			'tier'   => 1,
			'class'  => __('CLI', 'credentials'),
			'fields' => array(
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The SSH login username.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'auth_method' => array(
					'friendly_name' => __('Authentication Method', 'credentials'),
					'method'        => 'drop_array',
					'description'   => __('Authenticate with a password or a private key.', 'credentials'),
					'array'         => array('password' => __('Password', 'credentials'), 'key' => __('Private Key', 'credentials')),
					'default'       => 'password',
				),
				'password' => array(
					'friendly_name' => __('Password', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The SSH password (when using password authentication). Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => false,
					'max_length'    => 255,
				),
				'private_key' => array(
					'friendly_name' => __('Private Key', 'credentials'),
					'method'        => 'textarea',
					'description'   => __('The PEM private key (when using key authentication). Stored encrypted.', 'credentials'),
					'secret'        => true,
					'long'          => true,
					'required'      => false,
				),
				'passphrase' => array(
					'friendly_name' => __('Key Passphrase', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The optional passphrase protecting the private key. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => false,
					'max_length'    => 255,
				),
				'port' => array(
					'friendly_name' => __('Port', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The TCP port for the SSH service.', 'credentials'),
					'required'      => false,
					'default'       => '22',
					'max_length'    => 5,
				),
			),
		),

		/* ---------------- Tier 2: Modern API / cloud ---------------- */
		'bearer_token' => array(
			'name'   => __('Bearer / API Token', 'credentials'),
			'tier'   => 2,
			'class'  => __('API', 'credentials'),
			'fields' => array(
				'token' => array(
					'friendly_name' => __('Bearer Token', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The opaque bearer token sent as an Authorization header. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 1024,
				),
				'header_name' => array(
					'friendly_name' => __('Header Name', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The HTTP header the token is sent in.', 'credentials'),
					'required'      => false,
					'default'       => 'Authorization',
					'max_length'    => 128,
				),
			),
		),
		'api_key' => array(
			'name'   => __('API Key', 'credentials'),
			'tier'   => 2,
			'class'  => __('API', 'credentials'),
			'fields' => array(
				'key' => array(
					'friendly_name' => __('API Key', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The API key value. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 1024,
				),
				'placement' => array(
					'friendly_name' => __('Placement', 'credentials'),
					'method'        => 'drop_array',
					'description'   => __('Whether the key is sent as an HTTP header or a query parameter.', 'credentials'),
					'array'         => array('header' => __('Header', 'credentials'), 'query' => __('Query Parameter', 'credentials')),
					'default'       => 'header',
				),
				'param_name' => array(
					'friendly_name' => __('Parameter Name', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The header or query parameter name carrying the key (e.g. X-API-Key).', 'credentials'),
					'required'      => false,
					'default'       => 'X-API-Key',
					'max_length'    => 128,
				),
			),
		),
		'github_pat' => array(
			'name'   => __('GitHub Personal Access Token', 'credentials'),
			'tier'   => 2,
			'class'  => __('API', 'credentials'),
			'fields' => array(
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The optional GitHub username associated with the token.', 'credentials'),
					'required'      => false,
					'max_length'    => 255,
				),
				'token' => array(
					'friendly_name' => __('Personal Access Token', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The GitHub personal access token. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 1024,
				),
			),
		),
		'oauth2_client' => array(
			'name'   => __('OAuth 2.0 Client Credentials', 'credentials'),
			'tier'   => 2,
			'class'  => __('API', 'credentials'),
			'fields' => array(
				'client_id' => array(
					'friendly_name' => __('Client ID', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The OAuth 2.0 client identifier.', 'credentials'),
					'required'      => true,
					'max_length'    => 512,
				),
				'client_secret' => array(
					'friendly_name' => __('Client Secret', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The OAuth 2.0 client secret. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 1024,
				),
				'token_url' => array(
					'friendly_name' => __('Token URL', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The token endpoint used for the client_credentials grant.', 'credentials'),
					'required'      => true,
					'max_length'    => 512,
				),
				'scopes' => array(
					'friendly_name' => __('Scopes', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('An optional space delimited list of scopes to request.', 'credentials'),
					'required'      => false,
					'max_length'    => 512,
				),
			),
		),
		'http_basic' => array(
			'name'   => __('HTTP Basic Auth', 'credentials'),
			'tier'   => 2,
			'class'  => __('API', 'credentials'),
			'fields' => array(
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The HTTP Basic auth username.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'password' => array(
					'friendly_name' => __('Password', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The HTTP Basic auth password. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 255,
				),
			),
		),

		/* ---------------- Tier 3: Extended device coverage ---------------- */
		'wmi' => array(
			'name'   => __('WMI (Windows)', 'credentials'),
			'tier'   => 3,
			'class'  => __('Device', 'credentials'),
			'fields' => array(
				'domain' => array(
					'friendly_name' => __('Domain', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The optional Windows domain.', 'credentials'),
					'required'      => false,
					'max_length'    => 255,
				),
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The Windows account username.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'password' => array(
					'friendly_name' => __('Password', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The Windows account password. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 255,
				),
			),
		),
		'ipmi' => array(
			'name'   => __('IPMI / Redfish (BMC)', 'credentials'),
			'tier'   => 3,
			'class'  => __('Device', 'credentials'),
			'fields' => array(
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The out-of-band controller username.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'password' => array(
					'friendly_name' => __('Password', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The out-of-band controller password. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 255,
				),
				'protocol' => array(
					'friendly_name' => __('Protocol', 'credentials'),
					'method'        => 'drop_array',
					'description'   => __('The management protocol exposed by the controller.', 'credentials'),
					'array'         => array('ipmi' => 'IPMI', 'redfish' => 'Redfish'),
					'default'       => 'ipmi',
				),
			),
		),
		'database' => array(
			'name'   => __('Database', 'credentials'),
			'tier'   => 3,
			'class'  => __('Device', 'credentials'),
			'fields' => array(
				'driver' => array(
					'friendly_name' => __('Driver', 'credentials'),
					'method'        => 'drop_array',
					'description'   => __('The database engine this credential connects to.', 'credentials'),
					'array'         => array('mysql' => 'MySQL/MariaDB', 'pgsql' => 'PostgreSQL', 'mssql' => 'MS SQL Server', 'oracle' => 'Oracle'),
					'default'       => 'mysql',
				),
				'host' => array(
					'friendly_name' => __('Host', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The database server hostname or IP address.', 'credentials'),
					'required'      => false,
					'max_length'    => 255,
				),
				'port' => array(
					'friendly_name' => __('Port', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The database server TCP port.', 'credentials'),
					'required'      => false,
					'max_length'    => 5,
				),
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The database account username.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'password' => array(
					'friendly_name' => __('Password', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The database account password. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 255,
				),
				'database' => array(
					'friendly_name' => __('Database Name', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The optional default database/schema name.', 'credentials'),
					'required'      => false,
					'max_length'    => 255,
				),
			),
		),
		'vmware' => array(
			'name'   => __('VMware / vCenter', 'credentials'),
			'tier'   => 3,
			'class'  => __('Device', 'credentials'),
			'fields' => array(
				'server' => array(
					'friendly_name' => __('Server', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The vCenter or ESXi API endpoint.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'username' => array(
					'friendly_name' => __('Username', 'credentials'),
					'method'        => 'textbox',
					'description'   => __('The hypervisor API username.', 'credentials'),
					'required'      => true,
					'max_length'    => 255,
				),
				'password' => array(
					'friendly_name' => __('Password', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The hypervisor API password. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => true,
					'max_length'    => 255,
				),
			),
		),
		'tls_cert' => array(
			'name'   => __('TLS Client Certificate', 'credentials'),
			'tier'   => 3,
			'class'  => __('Device', 'credentials'),
			'fields' => array(
				'certificate' => array(
					'friendly_name' => __('Certificate (PEM)', 'credentials'),
					'method'        => 'textarea',
					'description'   => __('The PEM client certificate. Public material, stored as entered.', 'credentials'),
					'required'      => true,
				),
				'private_key' => array(
					'friendly_name' => __('Private Key (PEM)', 'credentials'),
					'method'        => 'textarea',
					'description'   => __('The PEM private key for the client certificate. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'long'          => true,
					'required'      => true,
				),
				'passphrase' => array(
					'friendly_name' => __('Key Passphrase', 'credentials'),
					'method'        => 'textbox_password',
					'description'   => __('The optional passphrase protecting the private key. Stored encrypted.', 'credentials'),
					'secret'        => true,
					'required'      => false,
					'max_length'    => 255,
				),
				'ca_bundle' => array(
					'friendly_name' => __('CA Bundle (PEM)', 'credentials'),
					'method'        => 'textarea',
					'description'   => __('An optional PEM CA bundle used to verify the peer.', 'credentials'),
					'required'      => false,
				),
			),
		),
	);

	return $types;
}

/**
 * Build the Credential Type drop-down option map (type code => display name),
 * grouped by tier for readability.
 *
 * @return array The option map for the credential type selector.
 */
function credentials_type_options(): array {
	$options = array();

	foreach (credentials_types() as $code => $type) {
		$options[$code] = __('Tier %d: %s', $type['tier'], $type['name'], 'credentials');
	}

	return $options;
}

/**
 * Return the definition for a single credential type.
 *
 * @param string $code The credential type code.
 *
 * @return array|false The type definition, or false when the code is unknown.
 */
function credentials_get_type(string $code): array|false {
	$types = credentials_types();

	return isset($types[$code]) ? $types[$code] : false;
}
