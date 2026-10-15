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
 * HashiCorp Vault driver. Supports the KV v1 and KV v2 secrets engines and two
 * auth methods: a static token, or AppRole (role_id + secret_id exchanged for a
 * short-lived token at resolve time). A reference names the secret path and the
 * key within it, for example 'secret/data/network/snmp#community' - or, more
 * simply, 'network/snmp#community' with the engine mount supplied by config.
 */
class VaultProvider extends AbstractProvider {
	public function type(): string {
		return 'vault';
	}

	public function label(): string {
		return __('HashiCorp Vault', 'credentials');
	}

	public function description(): string {
		return __('Resolve secrets from a HashiCorp Vault KV v1 or v2 secrets engine using a token or AppRole.', 'credentials');
	}

	public function referenceLabel(): string {
		return __('Secret Path and Key', 'credentials');
	}

	public function referenceHint(): string {
		return __('A Vault secret path and the key within it, separated by \'#\', for example \'network/snmp#community\'. The path is relative to the configured KV mount; append \'#key\' to select a field from the secret.', 'credentials');
	}

	public function configFields(): array {
		return array(
			'address' => array(
				'friendly_name' => __('Vault Address', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The base URL of the Vault server, for example https://vault.example.com:8200.', 'credentials'),
				'required'      => true,
				'max_length'    => 255,
			),
			'namespace' => array(
				'friendly_name' => __('Namespace', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The optional Vault Enterprise namespace (sent as the X-Vault-Namespace header).', 'credentials'),
				'max_length'    => 255,
			),
			'kv_version' => array(
				'friendly_name' => __('KV Engine Version', 'credentials'),
				'method'        => 'drop_array',
				'description'   => __('The version of the KV secrets engine the mount uses.', 'credentials'),
				'array'         => array('2' => __('KV Version 2', 'credentials'), '1' => __('KV Version 1', 'credentials')),
				'default'       => '2',
			),
			'mount' => array(
				'friendly_name' => __('KV Mount Path', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The mount path of the KV secrets engine, for example \'secret\'.', 'credentials'),
				'default'       => 'secret',
				'max_length'    => 128,
			),
			'auth_method' => array(
				'friendly_name' => __('Authentication Method', 'credentials'),
				'method'        => 'drop_array',
				'description'   => __('How this plugin authenticates to Vault.', 'credentials'),
				'array'         => array('token' => __('Token', 'credentials'), 'approle' => __('AppRole', 'credentials')),
				'default'       => 'token',
			),
			'token' => array(
				'friendly_name' => __('Token', 'credentials'),
				'method'        => 'textbox_password',
				'description'   => __('The Vault token used for Token authentication. Stored encrypted.', 'credentials'),
				'secret'        => true,
				'max_length'    => 255,
			),
			'role_id' => array(
				'friendly_name' => __('AppRole Role ID', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The AppRole RoleID used for AppRole authentication.', 'credentials'),
				'max_length'    => 255,
			),
			'secret_id' => array(
				'friendly_name' => __('AppRole Secret ID', 'credentials'),
				'method'        => 'textbox_password',
				'description'   => __('The AppRole SecretID used for AppRole authentication. Stored encrypted.', 'credentials'),
				'secret'        => true,
				'max_length'    => 255,
			),
			'tls_verify' => array(
				'friendly_name' => __('Verify TLS Certificate', 'credentials'),
				'method'        => 'checkbox',
				'description'   => __('Verify the Vault server TLS certificate. Disable only for testing.', 'credentials'),
				'default'       => 'on',
			),
			'ca_bundle_path' => array(
				'friendly_name' => __('CA Bundle Path', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('An optional path on the Cacti server to a PEM CA bundle used to verify Vault.', 'credentials'),
				'max_length'    => 255,
			),
			'timeout' => array(
				'friendly_name' => __('Timeout (seconds)', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The network timeout for Vault requests.', 'credentials'),
				'default'       => '15',
				'max_length'    => 4,
			),
		);
	}

	public function test(array $config): array {
		$address = $this->cfg($config, 'address');

		if ($address === '') {
			return array(false, __('A Vault address is required.', 'credentials'));
		}

		list($token, $err) = $this->authToken($config);

		if ($token === null) {
			return array(false, $err);
		}

		/* token lookup-self proves the token is valid and the server reachable */
		list($status, $body, $terr) = $this->http(
			$config,
			'GET',
			$this->base($config) . '/v1/auth/token/lookup-self',
			$this->vaultHeaders($config, $token)
		);

		if ($status === null) {
			return array(false, $terr);
		}

		if ($status >= 200 && $status < 300) {
			return array(true, __('Successfully authenticated to Vault.', 'credentials'));
		}

		return array(false, __('Vault returned HTTP %d during token verification.', $status, 'credentials'));
	}

	public function resolve(array $config, string $reference): array {
		list($path, $json_key) = $this->splitReference($reference);

		if ($path === '') {
			return array(false, null, __('A Vault secret path is required.', 'credentials'));
		}

		/* a reference with no '#key' and a KV v2 data document is ambiguous;
		 * default the key to the path leaf's common case only when selected */
		list($token, $err) = $this->authToken($config);

		if ($token === null) {
			return array(false, null, $err);
		}

		$kv_version = (string) $this->cfg($config, 'kv_version', '2');
		$mount      = trim((string) $this->cfg($config, 'mount', 'secret'), '/');
		$rel        = ltrim($path, '/');

		if ($kv_version === '2') {
			$api_path = $mount . '/data/' . $rel;
		} else {
			$api_path = $mount . '/' . $rel;
		}

		list($status, $body, $herr) = $this->http(
			$config,
			'GET',
			$this->base($config) . '/v1/' . $api_path,
			$this->vaultHeaders($config, $token)
		);

		if ($status === null) {
			return array(false, null, $herr);
		}

		if ($status === 404) {
			return array(false, null, __('The Vault secret path \'%s\' was not found.', $path, 'credentials'));
		}

		if ($status < 200 || $status >= 300) {
			return array(false, null, __('Vault returned HTTP %d reading the secret.', $status, 'credentials'));
		}

		$decoded = $this->decodeJson($body);

		if ($decoded === null || !isset($decoded['data'])) {
			return array(false, null, __('Vault returned an unexpected response reading the secret.', 'credentials'));
		}

		/* KV v2 nests the key/value map under data.data; KV v1 uses data */
		$data = ($kv_version === '2' && isset($decoded['data']['data']) && is_array($decoded['data']['data']))
			? $decoded['data']['data']
			: $decoded['data'];

		if (!is_array($data)) {
			return array(false, null, __('Vault returned an unexpected secret payload.', 'credentials'));
		}

		if ($json_key === null) {
			/* no key selected: only unambiguous when the secret holds one field */
			if (count($data) === 1) {
				$only = reset($data);

				return array(true, is_array($only) ? (string) json_encode($only) : (string) $only, '');
			}

			return array(false, null, __('The Vault secret holds multiple fields; append \'#key\' to the reference to select one.', 'credentials'));
		}

		/* delegate key selection - including dotted nested paths and structured
		 * values - to the shared helper the other drivers use */
		return $this->selectValue((string) json_encode($data), $json_key);
	}

	/**
	 * Resolve the token to present, performing an AppRole login when required.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [string|null token, string error] pair.
	 */
	private function authToken(array $config): array {
		$method = (string) $this->cfg($config, 'auth_method', 'token');

		if ($method === 'approle') {
			$role_id   = (string) $this->cfg($config, 'role_id');
			$secret_id = (string) $this->cfg($config, 'secret_id');

			if ($role_id === '' || $secret_id === '') {
				return array(null, __('AppRole authentication requires both a RoleID and a SecretID.', 'credentials'));
			}

			$payload = json_encode(array('role_id' => $role_id, 'secret_id' => $secret_id));

			list($status, $body, $err) = $this->http(
				$config,
				'POST',
				$this->base($config) . '/v1/auth/approle/login',
				$this->vaultHeaders($config, null),
				$payload
			);

			if ($status === null) {
				return array(null, $err);
			}

			if ($status < 200 || $status >= 300) {
				return array(null, __('Vault AppRole login failed with HTTP %d.', $status, 'credentials'));
			}

			$decoded = $this->decodeJson($body);

			if ($decoded === null || !isset($decoded['auth']['client_token'])) {
				return array(null, __('Vault AppRole login returned no client token.', 'credentials'));
			}

			return array((string) $decoded['auth']['client_token'], '');
		}

		$token = (string) $this->cfg($config, 'token');

		if ($token === '') {
			return array(null, __('A Vault token is required for Token authentication.', 'credentials'));
		}

		return array($token, '');
	}

	/**
	 * Build the common Vault request headers.
	 *
	 * @param array       $config The decrypted provider configuration.
	 * @param string|null $token  The Vault token, when one should be sent.
	 *
	 * @return array Header lines.
	 */
	private function vaultHeaders(array $config, ?string $token): array {
		$headers = array('Content-Type: application/json', 'Accept: application/json');

		$namespace = (string) $this->cfg($config, 'namespace');

		if ($namespace !== '') {
			$headers[] = 'X-Vault-Namespace: ' . $namespace;
		}

		if ($token !== null && $token !== '') {
			$headers[] = 'X-Vault-Token: ' . $token;
		}

		return $headers;
	}

	/**
	 * The Vault base URL with any trailing slash removed.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return string
	 */
	private function base(array $config): string {
		return rtrim((string) $this->cfg($config, 'address'), '/');
	}
}
