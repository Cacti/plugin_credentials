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
 * CyberArk Conjur driver (also covers Conjur Open Source and the Conjur-based
 * Secrets Manager). Authenticates a host or user identity with its API key to
 * obtain a short-lived access token, then reads a variable's value. A reference
 * is the Conjur variable id, with an optional '#key' to select a field from a
 * JSON secret value, for example 'prod/network/snmp#community'.
 */
class ConjurProvider extends AbstractProvider {
	public function type(): string {
		return 'conjur';
	}

	public function label(): string {
		return __('CyberArk Conjur', 'credentials');
	}

	public function description(): string {
		return __('Resolve secrets from CyberArk Conjur using a host or user identity and its API key.', 'credentials');
	}

	public function referenceLabel(): string {
		return __('Variable Id', 'credentials');
	}

	public function referenceHint(): string {
		return __('A Conjur variable id, with an optional \'#key\' to select a field from a JSON secret, for example \'prod/network/snmp\'.', 'credentials');
	}

	public function configFields(): array {
		return array(
			'appliance_url' => array(
				'friendly_name' => __('Appliance URL', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The base URL of the Conjur appliance, for example https://conjur.example.com.', 'credentials'),
				'required'      => true,
				'max_length'    => 255,
			),
			'account' => array(
				'friendly_name' => __('Account', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The Conjur account (organization) name.', 'credentials'),
				'required'      => true,
				'max_length'    => 128,
			),
			'login' => array(
				'friendly_name' => __('Login (Host or User)', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The identity used to authenticate, for example host/cacti-poller or a username.', 'credentials'),
				'required'      => true,
				'max_length'    => 255,
			),
			'api_key' => array(
				'friendly_name' => __('API Key', 'credentials'),
				'method'        => 'textbox_password',
				'description'   => __('The API key for the identity. Stored encrypted.', 'credentials'),
				'secret'        => true,
				'max_length'    => 255,
			),
			'tls_verify' => array(
				'friendly_name' => __('Verify TLS Certificate', 'credentials'),
				'method'        => 'checkbox',
				'description'   => __('Verify the Conjur appliance TLS certificate. Disable only for testing.', 'credentials'),
				'default'       => 'on',
			),
			'ca_bundle_path' => array(
				'friendly_name' => __('CA Bundle Path', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('An optional path on the Cacti server to a PEM CA bundle used to verify Conjur.', 'credentials'),
				'max_length'    => 255,
			),
			'timeout' => array(
				'friendly_name' => __('Timeout (seconds)', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The network timeout for Conjur requests.', 'credentials'),
				'default'       => '15',
				'max_length'    => 4,
			),
		);
	}

	public function test(array $config): array {
		foreach (array('appliance_url', 'account', 'login', 'api_key') as $required) {
			if ($this->cfg($config, $required) === '') {
				return array(false, __('The Conjur appliance URL, account, login and API key are all required.', 'credentials'));
			}
		}

		list($token, $err) = $this->authToken($config);

		if ($token === null) {
			return array(false, $err);
		}

		return array(true, __('Successfully authenticated to CyberArk Conjur.', 'credentials'));
	}

	public function resolve(array $config, string $reference): array {
		list($variable, $json_key) = $this->splitReference($reference);

		if ($variable === '') {
			return array(false, null, __('A Conjur variable id is required.', 'credentials'));
		}

		list($token, $err) = $this->authToken($config);

		if ($token === null) {
			return array(false, null, $err);
		}

		$account = (string) $this->cfg($config, 'account');

		$url = $this->base($config) . '/secrets/' . rawurlencode($account) . '/variable/' . $this->encodeVariable($variable);

		list($status, $body, $herr) = $this->http($config, 'GET', $url, array('Authorization: Token token="' . $token . '"'));

		if ($status === null) {
			return array(false, null, $herr);
		}

		if ($status === 404) {
			return array(false, null, __('The Conjur variable \'%s\' was not found or has no value.', $variable, 'credentials'));
		}

		if ($status < 200 || $status >= 300) {
			return array(false, null, __('Conjur returned HTTP %d reading the variable.', $status, 'credentials'));
		}

		return $this->selectValue($body, $json_key);
	}

	/**
	 * Authenticate the configured identity and return a base64 access token
	 * ready for the 'Authorization: Token token="..."' header.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [string|null token, string error] pair.
	 */
	private function authToken(array $config): array {
		$account = (string) $this->cfg($config, 'account');
		$login   = (string) $this->cfg($config, 'login');
		$api_key = (string) $this->cfg($config, 'api_key');

		if ($account === '' || $login === '' || $api_key === '') {
			return array(null, __('Conjur authentication requires an account, login and API key.', 'credentials'));
		}

		$url = $this->base($config) . '/authn/' . rawurlencode($account) . '/' . rawurlencode($login) . '/authenticate';

		list($status, $body, $err) = $this->http($config, 'POST', $url, array('Content-Type: text/plain', 'Accept-Encoding: base64'), $api_key);

		if ($status === null) {
			return array(null, $err);
		}

		if ($status < 200 || $status >= 300) {
			return array(null, __('Conjur authentication failed with HTTP %d.', $status, 'credentials'));
		}

		$token = trim($body);

		if ($token === '') {
			return array(null, __('Conjur authentication returned an empty token.', 'credentials'));
		}

		/* With 'Accept-Encoding: base64' Conjur returns the token already
		 * base64-encoded for the header; otherwise it returns raw JSON that
		 * must be base64-encoded here. */
		if ($this->looksBase64($token)) {
			return array($token, '');
		}

		return array(base64_encode($token), '');
	}

	/**
	 * Encode a slash-delimited Conjur variable id for use in a URL path. Conjur
	 * expects the id URL-encoded as a single path segment, so the separating
	 * slashes are themselves percent-encoded.
	 *
	 * @param string $variable The variable id.
	 *
	 * @return string
	 */
	private function encodeVariable(string $variable): string {
		$segments = array_map('rawurlencode', explode('/', ltrim($variable, '/')));

		return implode('%2F', $segments);
	}

	/**
	 * Heuristic: whether a token already looks base64-encoded (no JSON braces
	 * and only base64 alphabet characters).
	 *
	 * @param string $token The token string.
	 *
	 * @return bool
	 */
	private function looksBase64(string $token): bool {
		if (strpos($token, '{') !== false) {
			return false;
		}

		return (bool) preg_match('#^[A-Za-z0-9+/=]+$#', $token);
	}

	/**
	 * The appliance base URL with any trailing slash removed.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return string
	 */
	private function base(array $config): string {
		return rtrim((string) $this->cfg($config, 'appliance_url'), '/');
	}
}
