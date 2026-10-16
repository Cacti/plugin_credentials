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

require_once(__DIR__ . '/providers.php');

/*
 * Cacti core's AES-256-GCM secret helpers (cacti_encrypt_secret /
 * cacti_encrypt_secret_with_key / cacti_decrypt_secret /
 * cacti_decrypt_secret_with_key / cacti_secret_key) were added on the 1.2.x
 * branch in 1.2.32. On an older but supported release - this plugin's declared
 * floor is 1.2.29 - they are absent, so the credential store could not encrypt
 * a secret. When the running Cacti is older than 1.2.32, define a byte-for-byte
 * compatible copy of those core functions here so secret storage still works;
 * on 1.2.32+ core already provides them and every block below is skipped, so the
 * plugin always uses core's own implementation when it exists. See README.md.
 */
if (defined('CACTI_VERSION') && function_exists('cacti_version_compare') && cacti_version_compare(CACTI_VERSION, '1.2.32', '<')) {
	if (!defined('CACTI_SECRET_CIPHER')) {
		define('CACTI_SECRET_CIPHER', 'aes-256-gcm');
	}

	if (!defined('CACTI_SECRET_TAG_LENGTH')) {
		define('CACTI_SECRET_TAG_LENGTH', 16);
	}

	if (!function_exists('cacti_secret_key')) {
		function cacti_secret_key(): string {
			$key = read_config_option('secret_encryption_key');

			if (empty($key)) {
				$key = base64_encode(random_bytes(32));

				// INSERT IGNORE: keep a concurrently-stored key rather than clobbering it.
				db_execute_prepared('INSERT IGNORE INTO settings (`name`, `value`) VALUES (?, ?)', array('secret_encryption_key', $key));

				$key = (string) read_config_option('secret_encryption_key', true);
			}

			$decoded = base64_decode($key, true);

			if ($decoded === false || strlen($decoded) !== 32) {
				throw new \RuntimeException('The secret_encryption_key setting is missing or corrupt; encrypted secrets cannot be read or written until it is restored.');
			}

			return $decoded;
		}
	}

	if (!function_exists('cacti_encrypt_secret_with_key')) {
		function cacti_encrypt_secret_with_key(string $plaintext, string $key): string {
			if ($plaintext === '') {
				return '';
			}

			$iv  = openssl_random_pseudo_bytes(openssl_cipher_iv_length(CACTI_SECRET_CIPHER));
			$tag = '';

			$encrypted = openssl_encrypt($plaintext, CACTI_SECRET_CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, '', CACTI_SECRET_TAG_LENGTH);

			if ($encrypted === false) {
				// openssl only fails here on an internal/library error, not reachable from a unit test
				// @codeCoverageIgnoreStart
				throw new \RuntimeException('Failed to encrypt secret.');
				// @codeCoverageIgnoreEnd
			}

			return base64_encode($iv . $tag . $encrypted);
		}
	}

	if (!function_exists('cacti_decrypt_secret_with_key')) {
		function cacti_decrypt_secret_with_key(string $ciphertext, string $key): string|false {
			if ($ciphertext === '') {
				return '';
			}

			$raw = base64_decode($ciphertext, true);

			$iv_length  = openssl_cipher_iv_length(CACTI_SECRET_CIPHER);
			$tag_length = CACTI_SECRET_TAG_LENGTH;

			if ($raw === false || strlen($raw) <= $iv_length + $tag_length) {
				return false;
			}

			$iv         = substr($raw, 0, $iv_length);
			$tag        = substr($raw, $iv_length, $tag_length);
			$ciphertext = substr($raw, $iv_length + $tag_length);

			return openssl_decrypt($ciphertext, CACTI_SECRET_CIPHER, $key, OPENSSL_RAW_DATA, $iv, $tag, '');
		}
	}

	if (!function_exists('cacti_encrypt_secret')) {
		function cacti_encrypt_secret(string $plaintext): string {
			return cacti_encrypt_secret_with_key($plaintext, cacti_secret_key());
		}
	}

	if (!function_exists('cacti_decrypt_secret')) {
		function cacti_decrypt_secret(string $ciphertext): string|false {
			try {
				$key = cacti_secret_key();
			} catch (\RuntimeException $e) {
				cacti_log('ERROR: ' . $e->getMessage(), false, 'AUTH');

				return false;
			}

			return cacti_decrypt_secret_with_key($ciphertext, $key);
		}
	}
}

/**
 * Whether the core secret-encryption facility is usable on this install.
 * Callers must check this before credentials_encrypt(); credentials.php fails
 * closed (refusing to store a secret) when it returns false.
 *
 * @return bool True when a supported cacti_encrypt_secret* function exists.
 */
function credentials_encryption_available(): bool {
	return function_exists('cacti_encrypt_secret') ||
		(function_exists('cacti_encrypt_secret_with_key') && function_exists('cacti_secret_key'));
}

/**
 * Encrypt a secret value using the Cacti core secret functions, preferring
 * cacti_encrypt_secret() (per-installation key). Availability must be confirmed
 * by the caller via credentials_encryption_available() first.
 *
 * @param string $plaintext The secret to encrypt.
 *
 * @return string The base64 encrypted value, or '' for empty input.
 */
function credentials_encrypt(string $plaintext): string {
	if ($plaintext === '') {
		return '';
	}

	return function_exists('cacti_encrypt_secret')
		? cacti_encrypt_secret($plaintext)
		: cacti_encrypt_secret_with_key($plaintext, cacti_secret_key());
}

/**
 * Encrypt a secret, converting any core failure (missing/corrupt key, OpenSSL
 * error) into a handled result instead of an uncaught exception so a save can
 * fail gracefully. The caught message is a fixed core string and never carries
 * the plaintext, so logging it does not leak the secret.
 *
 * @param string $plaintext The secret to encrypt.
 *
 * @return array A [bool success, string ciphertext] pair; ciphertext is '' on failure.
 */
function credentials_try_encrypt(string $plaintext): array {
	try {
		return array(true, credentials_encrypt($plaintext));
	} catch (\Throwable $e) {
		cacti_log('ERROR: CREDENTIALS - secret encryption failed: ' . $e->getMessage(), false, 'CREDENTIALS');

		return array(false, '');
	}
}

/**
 * Validate mode-dependent (cross-field) requirements for a credential type: an
 * SSH credential needs the secret matching its chosen auth method, and an SNMP
 * v3 credential needs a valid USM security level with the matching passphrases.
 *
 * @param string $type  The credential type code.
 * @param array  $props The assembled property map (secrets already encrypted).
 *
 * @return string An error message, or '' when the cross-field rules are met.
 */
function credentials_cross_field_error(string $type, array $props): string {
	if ($type === 'ssh') {
		$method = isset($props['auth_method']) ? $props['auth_method'] : '';

		if ($method === 'password' && empty($props['password'])) {
			return __('A password is required for SSH password authentication.', 'credentials');
		}

		if ($method === 'key' && empty($props['private_key'])) {
			return __('A private key is required for SSH key authentication.', 'credentials');
		}
	} elseif ($type === 'snmpv3') {
		$auth = isset($props['auth_protocol']) ? $props['auth_protocol'] : 'none';
		$priv = isset($props['priv_protocol']) ? $props['priv_protocol'] : 'none';

		if ($priv !== 'none' && $auth === 'none') {
			return __('SNMP v3 privacy requires an authentication protocol; noAuthPriv is not a valid security level.', 'credentials');
		}

		if ($auth !== 'none' && empty($props['auth_passphrase'])) {
			return __('An authentication passphrase is required when an SNMP v3 authentication protocol is selected.', 'credentials');
		}

		if ($priv !== 'none' && empty($props['priv_passphrase'])) {
			return __('A privacy passphrase is required when an SNMP v3 privacy protocol is selected.', 'credentials');
		}
	}

	return '';
}

/**
 * Decrypt a secret previously stored by this plugin. Provided for consumers of
 * the credential store; the management UI never decrypts for display.
 *
 * @param string $ciphertext The stored (encrypted) value.
 *
 * @return string|false The decrypted secret, '' for empty input, or false when
 *                      the value cannot be decrypted.
 */
function credentials_decrypt(string $ciphertext): string|false {
	if ($ciphertext === '') {
		return '';
	}

	return function_exists('cacti_decrypt_secret')
		? cacti_decrypt_secret($ciphertext)
		: cacti_decrypt_secret_with_key($ciphertext, cacti_secret_key());
}

/**
 * Decode the JSON properties blob of a stored credential row.
 *
 * @param array $credential A credentials table row.
 *
 * @return array The decoded property map, or an empty array.
 */
function credentials_properties(array $credential): array {
	if (!isset($credential['properties']) || $credential['properties'] === '') {
		return array();
	}

	$props = json_decode($credential['properties'], true);

	return is_array($props) ? $props : array();
}

/**
 * Whether a given field of a stored credential currently holds a secret value.
 * Used to drive the "a value is stored" masking hint on the edit form.
 *
 * @param array  $props The decoded property map.
 * @param string $field The field name.
 *
 * @return bool True when a non-empty stored value exists for the field.
 */
function credentials_secret_is_set(array $props, string $field): bool {
	return isset($props[$field]) && $props[$field] !== '';
}

/**
 * Fetch and resolve a single credential, returning its non-secret fields as
 * stored and its secret fields as live plaintext. For a credential backed by
 * the local store the secret is decrypted; for one backed by an external
 * provider the stored reference is resolved through the provider driver.
 * Intended for other Cacti code and plugins that need a credential at poll time.
 *
 * @param int $id The credential id.
 *
 * @return array|false The credential meta (including 'provider_id') plus a
 *                     'fields' map, or false when the credential does not exist.
 */
function credentials_get(int $id): array|false {
	$credential = db_fetch_row_prepared('SELECT * FROM credentials WHERE id = ?', array($id));

	if (!is_array($credential) || cacti_sizeof($credential) == 0) {
		return false;
	}

	$type        = credentials_get_type($credential['type']);
	$props       = credentials_properties($credential);
	$provider_id = isset($credential['provider_id']) ? (int) $credential['provider_id'] : 0;
	$fields      = array();

	if (is_array($type)) {
		foreach ($type['fields'] as $name => $def) {
			$value = isset($props[$name]) ? $props[$name] : '';

			if (!empty($def['secret']) && $value !== '') {
				if ($provider_id > 0) {
					/* an external provider stores a reference, not ciphertext:
					 * resolve it to the live secret through the provider driver */
					$value = credentials_provider_resolve_reference($provider_id, $value);
				} else {
					$value = credentials_decrypt($value);
				}
			}

			$fields[$name] = $value;
		}
	}

	return array(
		'id'           => $credential['id'],
		'name'         => $credential['name'],
		'description'  => $credential['description'],
		'type'         => $credential['type'],
		'provider_id'  => $provider_id,
		'user_id'      => $credential['user_id'],
		'enabled'      => $credential['enabled'],
		'create_date'  => $credential['create_date'],
		'last_updated' => $credential['last_updated'],
		'fields'       => $fields,
	);
}
