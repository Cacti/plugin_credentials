<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Regression coverage for the Google service-account token endpoint. A
 * credential file must not be able to redirect the signed JWT to another host.
 */

require_once __DIR__ . '/../../setup.php';
require_once __DIR__ . '/../../includes/providers.php';

class CredentialsTokenUriTestProvider extends GcpSecretManagerProvider {
	public array $requests  = array();
	public array $responses = array();

	protected function http(array $config, string $method, string $url, array $headers = array(), ?string $body = null): array {
		$this->requests[] = array('method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body);

		return array_shift($this->responses);
	}
}

/**
 * Create a private key for provider tests without using a real service account.
 *
 * @return string A PEM-encoded RSA private key.
 */
function credentials_token_uri_test_private_key(): string {
	$key = openssl_pkey_new(array(
		'private_key_bits' => 2048,
		'private_key_type' => OPENSSL_KEYTYPE_RSA,
	));
	openssl_pkey_export($key, $private_key);

	return $private_key;
}

/**
 * Build a service-account config with a supplied token endpoint.
 *
 * @param string $token_uri The service-account token endpoint.
 *
 * @return array The provider config passed to the GCP driver.
 */
function credentials_token_uri_test_config(mixed $token_uri = null, bool $include_token_uri = true): array {
	$service_account = array(
		'client_email' => 'test@example.iam.gserviceaccount.com',
		'private_key'  => credentials_token_uri_test_private_key(),
	);

	if ($include_token_uri) {
		$service_account['token_uri'] = $token_uri;
	}

	return array('service_account_json' => json_encode($service_account));
}

it('uses only supported Google OAuth endpoints for token exchange', function () {
	$endpoints = array(
		array(array(null, false), 'https://oauth2.googleapis.com/token'),
		array(array('https://oauth2.googleapis.com/token'), 'https://oauth2.googleapis.com/token'),
		array(array('https://accounts.google.com/o/oauth2/token'), 'https://accounts.google.com/o/oauth2/token'),
		array(array('https://oauth2.googleapis.com:443/token'), 'https://oauth2.googleapis.com:443/token'),
	);

	foreach ($endpoints as list($token_uri_config, $expected_uri)) {
		$provider = new CredentialsTokenUriTestProvider();
		$provider->responses = array(
			array(200, json_encode(array('access_token' => 'test-token')), ''),
			array(200, json_encode(array('payload' => array('data' => base64_encode('test-secret')))), ''),
		);

		list($ok, $value, $error) = $provider->resolve(
			credentials_token_uri_test_config(...$token_uri_config),
			'secret-name'
		);

		expect($ok)->toBeTrue()
			->and($value)->toBe('test-secret')
			->and($error)->toBe('')
			->and($provider->requests[0]['url'])->toBe($expected_uri);
	}
});

it('rejects untrusted or malformed token endpoints before sending the signed JWT', function () {
	$http_scheme = 'http';
	$invalid_uris = array(
		$http_scheme . '://oauth2.googleapis.com/token',
		'https://oauth2.googleapis.com.attacker.example/token',
		'https://user@oauth2.googleapis.com/token',
		'https://user:password@oauth2.googleapis.com/token',
		'https://oauth2.googleapis.com/token?redirect=attacker',
		'https://oauth2.googleapis.com/token#fragment',
		'https://oauth2.googleapis.com:444/token',
		'https://oauth2.googleapis.com/other',
		'file:///tmp/token',
		null,
		'',
		array('https://oauth2.googleapis.com/token'),
	);

	foreach ($invalid_uris as $uri) {
		$provider = new CredentialsTokenUriTestProvider();
		list($ok, $value, $error) = $provider->resolve(credentials_token_uri_test_config($uri), 'secret-name');

		expect($ok)->toBeFalse()
			->and($value)->toBeNull()
			->and($error)->toBe('The service account token URI must be a supported Google OAuth endpoint.')
			->and($provider->requests)->toBe([]);
	}
});
