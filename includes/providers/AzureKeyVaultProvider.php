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
 * Azure Key Vault driver. Authenticates with either an Entra ID (Azure AD)
 * service principal using the client-credentials OAuth2 flow, or the instance's
 * Managed Identity via the IMDS token endpoint, then reads a secret from the
 * vault's data-plane REST API. A reference is the secret name, optionally with
 * a version ('name/version') and an optional '#key' to select a field from a
 * JSON secret value.
 */
class AzureKeyVaultProvider extends AbstractProvider {
	/** The Key Vault data-plane scope requested for access tokens. */
	private const SCOPE = 'https://vault.azure.net/.default';

	/** The Key Vault resource for Managed Identity token requests. */
	private const RESOURCE = 'https://vault.azure.net';

	public function type(): string {
		return 'azure';
	}

	public function label(): string {
		return __('Azure Key Vault', 'credentials');
	}

	public function description(): string {
		return __('Resolve secrets from Azure Key Vault using an Entra ID service principal or a Managed Identity.', 'credentials');
	}

	public function referenceLabel(): string {
		return __('Secret Name', 'credentials');
	}

	public function referenceHint(): string {
		return __('A Key Vault secret name, optionally a specific version as \'name/version\', with an optional \'#key\' to select a field from a JSON secret, for example \'snmp-community\'.', 'credentials');
	}

	public function configFields(): array {
		return array(
			'vault_url' => array(
				'friendly_name' => __('Vault URL', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The Key Vault base URL, for example https://my-vault.vault.azure.net.', 'credentials'),
				'required'      => true,
				'max_length'    => 255,
			),
			'auth_method' => array(
				'friendly_name' => __('Authentication Method', 'credentials'),
				'method'        => 'drop_array',
				'description'   => __('How this plugin obtains an access token.', 'credentials'),
				'array'         => array(
					'client_secret'    => __('Service Principal (client secret)', 'credentials'),
					'managed_identity' => __('Managed Identity', 'credentials'),
				),
				'default'       => 'client_secret',
			),
			'tenant_id' => array(
				'friendly_name' => __('Tenant Id', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The Entra ID tenant (directory) id, used for service principal authentication.', 'credentials'),
				'max_length'    => 128,
			),
			'client_id' => array(
				'friendly_name' => __('Client Id', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The application (client) id. For a user-assigned Managed Identity, the identity client id.', 'credentials'),
				'max_length'    => 128,
			),
			'client_secret' => array(
				'friendly_name' => __('Client Secret', 'credentials'),
				'method'        => 'textbox_password',
				'description'   => __('The service principal client secret. Stored encrypted.', 'credentials'),
				'secret'        => true,
				'max_length'    => 255,
			),
			'api_version' => array(
				'friendly_name' => __('API Version', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The Key Vault data-plane API version.', 'credentials'),
				'default'       => '7.4',
				'max_length'    => 16,
			),
			'timeout' => array(
				'friendly_name' => __('Timeout (seconds)', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The network timeout for Azure requests.', 'credentials'),
				'default'       => '15',
				'max_length'    => 4,
			),
		);
	}

	public function test(array $config): array {
		if ($this->cfg($config, 'vault_url') === '') {
			return array(false, __('A Key Vault URL is required.', 'credentials'));
		}

		list($token, $err) = $this->accessToken($config);

		if ($token === null) {
			return array(false, $err);
		}

		/* listing a single secret proves data-plane access without naming one */
		$url = rtrim((string) $this->cfg($config, 'vault_url'), '/') . '/secrets?maxresults=1&api-version=' . rawurlencode((string) $this->cfg($config, 'api_version', '7.4'));

		list($status, $body, $herr) = $this->http($config, 'GET', $url, array('Authorization: Bearer ' . $token, 'Accept: application/json'));

		if ($status === null) {
			return array(false, $herr);
		}

		if ($status >= 200 && $status < 300) {
			return array(true, __('Successfully authenticated to Azure Key Vault.', 'credentials'));
		}

		return array(false, $this->apiError($status, $body));
	}

	public function resolve(array $config, string $reference): array {
		list($locator, $json_key) = $this->splitReference($reference);

		if ($locator === '') {
			return array(false, null, __('A Key Vault secret name is required.', 'credentials'));
		}

		list($token, $err) = $this->accessToken($config);

		if ($token === null) {
			return array(false, null, $err);
		}

		/* 'name' or 'name/version' - version is optional */
		$parts   = explode('/', $locator, 2);
		$name    = rawurlencode($parts[0]);
		$version = isset($parts[1]) && $parts[1] !== '' ? '/' . rawurlencode($parts[1]) : '';

		$url = rtrim((string) $this->cfg($config, 'vault_url'), '/') . '/secrets/' . $name . $version
			. '?api-version=' . rawurlencode((string) $this->cfg($config, 'api_version', '7.4'));

		list($status, $body, $herr) = $this->http($config, 'GET', $url, array('Authorization: Bearer ' . $token, 'Accept: application/json'));

		if ($status === null) {
			return array(false, null, $herr);
		}

		if ($status === 404) {
			return array(false, null, __('The Key Vault secret \'%s\' was not found.', $parts[0], 'credentials'));
		}

		if ($status < 200 || $status >= 300) {
			return array(false, null, $this->apiError($status, $body));
		}

		$decoded = $this->decodeJson($body);

		if ($decoded === null || !isset($decoded['value'])) {
			return array(false, null, __('Azure returned an unexpected response reading the secret.', 'credentials'));
		}

		return $this->selectValue((string) $decoded['value'], $json_key);
	}

	/**
	 * Obtain an access token for the Key Vault data plane.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [string|null token, string error] pair.
	 */
	private function accessToken(array $config): array {
		if ((string) $this->cfg($config, 'auth_method', 'client_secret') === 'managed_identity') {
			return $this->managedIdentityToken($config);
		}

		$tenant = (string) $this->cfg($config, 'tenant_id');
		$client = (string) $this->cfg($config, 'client_id');
		$secret = (string) $this->cfg($config, 'client_secret');

		if ($tenant === '' || $client === '' || $secret === '') {
			return array(null, __('Service principal authentication requires a tenant id, client id and client secret.', 'credentials'));
		}

		$url  = 'https://login.microsoftonline.com/' . rawurlencode($tenant) . '/oauth2/v2.0/token';
		$body = http_build_query(array(
			'grant_type'    => 'client_credentials',
			'client_id'     => $client,
			'client_secret' => $secret,
			'scope'         => self::SCOPE,
		));

		list($status, $resp, $err) = $this->http($config, 'POST', $url, array('Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'), $body);

		if ($status === null) {
			return array(null, $err);
		}

		if ($status < 200 || $status >= 300) {
			return array(null, __('Azure token request failed with HTTP %d.', $status, 'credentials'));
		}

		$decoded = $this->decodeJson($resp);

		if ($decoded === null || !isset($decoded['access_token'])) {
			return array(null, __('Azure token request returned no access token.', 'credentials'));
		}

		return array((string) $decoded['access_token'], '');
	}

	/**
	 * Obtain an access token from the instance Managed Identity endpoint.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [string|null token, string error] pair.
	 */
	private function managedIdentityToken(array $config): array {
		$url = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=' . rawurlencode(self::RESOURCE);

		$client = (string) $this->cfg($config, 'client_id');

		if ($client !== '') {
			$url .= '&client_id=' . rawurlencode($client);
		}

		list($status, $resp, $err) = $this->http($config, 'GET', $url, array('Metadata: true', 'Accept: application/json'));

		if ($status === null || $status < 200 || $status >= 300) {
			return array(null, __('Unable to obtain a Managed Identity token; is Cacti running on an Azure resource with an identity assigned?', 'credentials'));
		}

		$decoded = $this->decodeJson($resp);

		if ($decoded === null || !isset($decoded['access_token'])) {
			return array(null, __('The Managed Identity endpoint returned no access token.', 'credentials'));
		}

		return array((string) $decoded['access_token'], '');
	}

	/**
	 * Turn an error response into a concise, non-sensitive message.
	 *
	 * @param int    $status The HTTP status code.
	 * @param string $body   The response body.
	 *
	 * @return string
	 */
	private function apiError(int $status, string $body): string {
		$decoded = json_decode($body, true);

		if (is_array($decoded) && isset($decoded['error']['message'])) {
			return __('Azure Key Vault error: %s (HTTP %d).', (string) $decoded['error']['message'], $status, 'credentials');
		}

		return __('Azure Key Vault returned HTTP %d.', $status, 'credentials');
	}
}
