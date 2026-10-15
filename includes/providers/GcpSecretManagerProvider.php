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
 * Google Cloud Secret Manager driver. Authenticates with a service-account JSON
 * key by minting a signed JWT (RS256) and exchanging it for an OAuth2 access
 * token, or - when 'Use Instance Service Account' is set - by reading a token
 * from the GCE metadata server. It then accesses a secret version. A reference
 * is the secret id, optionally a version as 'name/version' (default 'latest'),
 * with an optional '#key' to select a field from a JSON secret payload.
 */
class GcpSecretManagerProvider extends AbstractProvider {
	/** The OAuth2 scope required to access secret versions. */
	private const SCOPE = 'https://www.googleapis.com/auth/cloud-platform';

	public function type(): string {
		return 'gcp';
	}

	public function label(): string {
		return __('Google Cloud Secret Manager', 'credentials');
	}

	public function description(): string {
		return __('Resolve secrets from Google Cloud Secret Manager using a service account key or the instance service account.', 'credentials');
	}

	public function referenceLabel(): string {
		return __('Secret Name', 'credentials');
	}

	public function referenceHint(): string {
		return __('A Secret Manager secret id, optionally a version as \'name/version\' (default \'latest\'), with an optional \'#key\' to select a field from a JSON secret, for example \'snmp-community\'.', 'credentials');
	}

	public function configFields(): array {
		return array(
			'project_id' => array(
				'friendly_name' => __('Project Id', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The Google Cloud project id that owns the secrets.', 'credentials'),
				'required'      => true,
				'max_length'    => 128,
			),
			'use_instance_sa' => array(
				'friendly_name' => __('Use Instance Service Account', 'credentials'),
				'method'        => 'checkbox',
				'description'   => __('Obtain an access token from the GCE metadata server instead of a service account key.', 'credentials'),
				'default'       => '',
			),
			'service_account_json' => array(
				'friendly_name' => __('Service Account Key (JSON)', 'credentials'),
				'method'        => 'textarea',
				'description'   => __('The full service account key JSON. Stored encrypted. Not required when using the instance service account.', 'credentials'),
				'secret'        => true,
				'long'          => true,
			),
			'timeout' => array(
				'friendly_name' => __('Timeout (seconds)', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The network timeout for Google Cloud requests.', 'credentials'),
				'default'       => '15',
				'max_length'    => 4,
			),
		);
	}

	public function test(array $config): array {
		if ($this->cfg($config, 'project_id') === '') {
			return array(false, __('A Google Cloud project id is required.', 'credentials'));
		}

		list($token, $err) = $this->accessToken($config);

		if ($token === null) {
			return array(false, $err);
		}

		/* listing secrets with a page size of 1 proves access to the project */
		$url = 'https://secretmanager.googleapis.com/v1/projects/' . rawurlencode((string) $this->cfg($config, 'project_id')) . '/secrets?pageSize=1';

		list($status, $body, $herr) = $this->http($config, 'GET', $url, array('Authorization: Bearer ' . $token, 'Accept: application/json'));

		if ($status === null) {
			return array(false, $herr);
		}

		if ($status >= 200 && $status < 300) {
			return array(true, __('Successfully authenticated to Google Cloud Secret Manager.', 'credentials'));
		}

		return array(false, $this->apiError($status, $body));
	}

	public function resolve(array $config, string $reference): array {
		list($locator, $json_key) = $this->splitReference($reference);

		if ($locator === '') {
			return array(false, null, __('A Secret Manager secret name is required.', 'credentials'));
		}

		list($token, $err) = $this->accessToken($config);

		if ($token === null) {
			return array(false, null, $err);
		}

		$parts   = explode('/', $locator, 2);
		$name    = rawurlencode($parts[0]);
		$version = isset($parts[1]) && $parts[1] !== '' ? rawurlencode($parts[1]) : 'latest';

		$url = 'https://secretmanager.googleapis.com/v1/projects/' . rawurlencode((string) $this->cfg($config, 'project_id'))
			. '/secrets/' . $name . '/versions/' . $version . ':access';

		list($status, $body, $herr) = $this->http($config, 'GET', $url, array('Authorization: Bearer ' . $token, 'Accept: application/json'));

		if ($status === null) {
			return array(false, null, $herr);
		}

		if ($status === 404) {
			return array(false, null, __('The Secret Manager secret \'%s\' was not found.', $parts[0], 'credentials'));
		}

		if ($status < 200 || $status >= 300) {
			return array(false, null, $this->apiError($status, $body));
		}

		$decoded = $this->decodeJson($body);

		if ($decoded === null || !isset($decoded['payload']['data'])) {
			return array(false, null, __('Google Cloud returned an unexpected response reading the secret.', 'credentials'));
		}

		$payload = base64_decode((string) $decoded['payload']['data'], true);

		if ($payload === false) {
			return array(false, null, __('The Secret Manager payload could not be decoded.', 'credentials'));
		}

		return $this->selectValue($payload, $json_key);
	}

	/**
	 * Obtain an OAuth2 access token, either by signing a service-account JWT or
	 * from the GCE metadata server.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [string|null token, string error] pair.
	 */
	private function accessToken(array $config): array {
		if ($this->flag($config, 'use_instance_sa', false)) {
			return $this->metadataToken($config);
		}

		$raw = (string) $this->cfg($config, 'service_account_json');

		if ($raw === '') {
			return array(null, __('A service account key JSON is required unless the instance service account is used.', 'credentials'));
		}

		$sa = json_decode($raw, true);

		if (!is_array($sa) || !isset($sa['client_email'], $sa['private_key'])) {
			return array(null, __('The service account key JSON is invalid or incomplete.', 'credentials'));
		}

		$token_uri = isset($sa['token_uri']) ? (string) $sa['token_uri'] : 'https://oauth2.googleapis.com/token';
		$now       = time();

		$claims = array(
			'iss'   => $sa['client_email'],
			'scope' => self::SCOPE,
			'aud'   => $token_uri,
			'iat'   => $now,
			'exp'   => $now + 3600,
		);

		list($jwt, $jerr) = self::signJwt($claims, (string) $sa['private_key']);

		if ($jwt === null) {
			return array(null, $jerr);
		}

		$body = http_build_query(array(
			'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
			'assertion'  => $jwt,
		));

		list($status, $resp, $err) = $this->http($config, 'POST', $token_uri, array('Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'), $body);

		if ($status === null) {
			return array(null, $err);
		}

		if ($status < 200 || $status >= 300) {
			return array(null, __('Google Cloud token request failed with HTTP %d.', $status, 'credentials'));
		}

		$decoded = $this->decodeJson($resp);

		if ($decoded === null || !isset($decoded['access_token'])) {
			return array(null, __('Google Cloud token request returned no access token.', 'credentials'));
		}

		return array((string) $decoded['access_token'], '');
	}

	/**
	 * Read an access token from the GCE metadata server.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [string|null token, string error] pair.
	 */
	private function metadataToken(array $config): array {
		$url = 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';

		list($status, $resp, $err) = $this->http($config, 'GET', $url, array('Metadata-Flavor: Google', 'Accept: application/json'));

		if ($status === null || $status < 200 || $status >= 300) {
			return array(null, __('Unable to obtain a token from the GCE metadata server; is Cacti running on a Google Cloud instance?', 'credentials'));
		}

		$decoded = $this->decodeJson($resp);

		if ($decoded === null || !isset($decoded['access_token'])) {
			return array(null, __('The GCE metadata server returned no access token.', 'credentials'));
		}

		return array((string) $decoded['access_token'], '');
	}

	/**
	 * Build and RS256-sign a JWT. Pure and deterministic given a fixed key and
	 * claims, so it can be verified without a network.
	 *
	 * @param array  $claims      The JWT claim set.
	 * @param string $private_key The PEM RSA private key.
	 *
	 * @return array A [string|null jwt, string error] pair.
	 */
	public static function signJwt(array $claims, string $private_key): array {
		$header  = self::base64Url((string) json_encode(array('alg' => 'RS256', 'typ' => 'JWT')));
		$payload = self::base64Url((string) json_encode($claims));
		$signing_input = $header . '.' . $payload;

		$key = openssl_pkey_get_private($private_key);

		if ($key === false) {
			return array(null, __('The service account private key could not be read.', 'credentials'));
		}

		$signature = '';
		$ok        = openssl_sign($signing_input, $signature, $key, OPENSSL_ALGO_SHA256);

		if (!$ok) {
			return array(null, __('The service account JWT could not be signed.', 'credentials'));
		}

		return array($signing_input . '.' . self::base64Url($signature), '');
	}

	/**
	 * URL-safe base64 without padding, as used by JWT.
	 *
	 * @param string $data The raw bytes to encode.
	 *
	 * @return string
	 */
	private static function base64Url(string $data): string {
		return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
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
			return __('Google Cloud Secret Manager error: %s (HTTP %d).', (string) $decoded['error']['message'], $status, 'credentials');
		}

		return __('Google Cloud Secret Manager returned HTTP %d.', $status, 'credentials');
	}
}
