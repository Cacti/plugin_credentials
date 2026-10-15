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
 * Shared behaviour for the HTTP-based secret-store drivers: a small cURL
 * wrapper honouring the common TLS/timeout configuration, plus the reference
 * parsing and JSON selection helpers every driver reuses. The class is free of
 * Cacti globals so the drivers can be exercised in isolation; callers in
 * includes/providers.php own the database access, decryption and logging.
 */
abstract class AbstractProvider implements CredentialProvider {
	/** Default per-request network timeout, in seconds. */
	protected const DEFAULT_TIMEOUT = 15;

	/**
	 * {@inheritDoc} Drivers that do not surface a bespoke reference label fall
	 * back to a generic one.
	 */
	public function referenceLabel(): string {
		return __('Secret Reference', 'credentials');
	}

	/**
	 * Read a single configuration value with a default, trimming strings so an
	 * accidentally padded endpoint or region does not break request building.
	 *
	 * @param array  $config  The decrypted provider configuration.
	 * @param string $key     The configuration field name.
	 * @param mixed  $default The value to return when the field is absent/empty.
	 *
	 * @return mixed
	 */
	protected function cfg(array $config, string $key, $default = '') {
		if (!isset($config[$key]) || $config[$key] === '') {
			return $default;
		}

		return is_string($config[$key]) ? trim($config[$key]) : $config[$key];
	}

	/**
	 * Whether a config flag rendered as a Cacti checkbox ('on'/'') is enabled.
	 *
	 * @param array  $config The decrypted provider configuration.
	 * @param string $key    The configuration field name.
	 * @param bool   $default Value to use when the field is absent.
	 *
	 * @return bool
	 */
	protected function flag(array $config, string $key, bool $default = false): bool {
		if (!isset($config[$key]) || $config[$key] === '') {
			return $default;
		}

		return $config[$key] === 'on' || $config[$key] === true || $config[$key] === '1' || $config[$key] === 1;
	}

	/**
	 * Split a stored reference into its store-side locator and an optional JSON
	 * key selector. The selector is the substring after the first '#'; it lets a
	 * single stored secret document expose several named values to different
	 * credential fields (for example 'kv/data/db#password').
	 *
	 * @param string $reference The stored reference.
	 *
	 * @return array A [string locator, string|null json_key] pair.
	 */
	protected function splitReference(string $reference): array {
		$reference = trim($reference);
		$hash      = strpos($reference, '#');

		if ($hash === false) {
			return array($reference, null);
		}

		$locator = substr($reference, 0, $hash);
		$json    = substr($reference, $hash + 1);

		return array(trim($locator), $json === '' ? null : $json);
	}

	/**
	 * Select the final secret value from a store payload. When a JSON key was
	 * requested the payload is decoded and the key extracted; otherwise the raw
	 * payload is returned unchanged. A requested key that is missing - or a
	 * payload that is not the JSON object a key implies - is a hard error so a
	 * misconfiguration never silently resolves to the wrong value.
	 *
	 * @param string      $payload  The raw value returned by the store.
	 * @param string|null $json_key The optional key to extract.
	 *
	 * @return array A [bool ok, string|null value, string error] triple.
	 */
	protected function selectValue(string $payload, ?string $json_key): array {
		if ($json_key === null) {
			return array(true, $payload, '');
		}

		$decoded = json_decode($payload, true);

		if (!is_array($decoded)) {
			return array(false, null, __('The stored secret is not a JSON object, so the \'%s\' key cannot be selected.', $json_key, 'credentials'));
		}

		$value = $decoded;

		/* allow dotted paths into nested JSON objects */
		foreach (explode('.', $json_key) as $segment) {
			if (!is_array($value) || !array_key_exists($segment, $value)) {
				return array(false, null, __('The stored secret does not contain the \'%s\' key.', $json_key, 'credentials'));
			}

			$value = $value[$segment];
		}

		if (is_array($value)) {
			$value = json_encode($value);
		}

		return array(true, (string) $value, '');
	}

	/**
	 * Perform an HTTP request with cURL, applying the driver's shared TLS and
	 * timeout configuration. Returns the transport outcome without interpreting
	 * it; each driver maps status codes to success or a diagnostic.
	 *
	 * @param array $config  The decrypted provider configuration (tls_verify,
	 *                       ca_bundle, timeout are honoured when present).
	 * @param string $method The HTTP method.
	 * @param string $url    The absolute request URL.
	 * @param array  $headers Header lines ('Name: value').
	 * @param string|null $body Optional request body.
	 *
	 * @return array A [int|null status, string body, string error] triple;
	 *               status is null on a transport failure and error is set.
	 */
	protected function http(array $config, string $method, string $url, array $headers = array(), ?string $body = null): array {
		if (!function_exists('curl_init')) {
			return array(null, '', __('The PHP cURL extension is required to reach external secret providers.', 'credentials'));
		}

		$ch = curl_init();

		$timeout = (int) $this->cfg($config, 'timeout', static::DEFAULT_TIMEOUT);

		if ($timeout <= 0) {
			$timeout = static::DEFAULT_TIMEOUT;
		}

		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, strtoupper($method));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
		curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

		/* TLS verification is on by default; it can be disabled only by an
		 * explicit 'tls_verify' => '' on drivers that expose the toggle, and a
		 * CA bundle path may pin verification to a private authority */
		$verify   = !isset($config['tls_verify']) ? true : $this->flag($config, 'tls_verify', true);
		$ca_path  = (string) $this->cfg($config, 'ca_bundle_path', '');

		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verify ? 2 : 0);

		if ($verify && $ca_path !== '' && is_readable($ca_path)) {
			curl_setopt($ch, CURLOPT_CAINFO, $ca_path);
		}

		if ($headers !== array()) {
			curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		}

		if ($body !== null) {
			curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
		}

		$response = curl_exec($ch);

		if ($response === false) {
			$err = curl_error($ch);
			curl_close($ch);

			return array(null, '', $err !== '' ? $err : __('The request to the secret provider failed.', 'credentials'));
		}

		$status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
		curl_close($ch);

		return array($status, (string) $response, '');
	}

	/**
	 * Decode a JSON response body into an array, tolerating an empty body.
	 *
	 * @param string $body The raw response body.
	 *
	 * @return array|null The decoded array, or null when the body is not a JSON
	 *                    object/array.
	 */
	protected function decodeJson(string $body): ?array {
		if (trim($body) === '') {
			return array();
		}

		$decoded = json_decode($body, true);

		return is_array($decoded) ? $decoded : null;
	}
}
