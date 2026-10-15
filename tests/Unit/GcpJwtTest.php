<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
 | http://www.cacti.net/                                                   |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit coverage for the RS256 JWT assertion the Google Cloud Secret Manager
 * driver signs for the service-account OAuth2 flow. A throwaway RSA key pair is
 * generated so the signature can be verified end to end without a network or a
 * real service account.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

function credentials_test_rsa_keypair(): array {
	$res = openssl_pkey_new(array(
		'private_key_bits' => 2048,
		'private_key_type' => OPENSSL_KEYTYPE_RSA,
	));

	openssl_pkey_export($res, $private);
	$details = openssl_pkey_get_details($res);

	return array($private, $details['key']);
}

function credentials_test_b64url_decode(string $data): string {
	return (string) base64_decode(strtr($data, '-_', '+/'), true);
}

it('signs a verifiable RS256 JWT with the documented header and claims', function () {
	list($private, $public) = credentials_test_rsa_keypair();

	$claims = array(
		'iss'   => 'poller@example.iam.gserviceaccount.com',
		'scope' => 'https://www.googleapis.com/auth/cloud-platform',
		'aud'   => 'https://oauth2.googleapis.com/token',
		'iat'   => 1700000000,
		'exp'   => 1700003600,
	);

	list($jwt, $error) = GcpSecretManagerProvider::signJwt($claims, $private);

	expect($error)->toBe('')
		->and($jwt)->toBeString();

	$parts = explode('.', $jwt);

	expect($parts)->toHaveCount(3);

	$header  = json_decode(credentials_test_b64url_decode($parts[0]), true);
	$payload = json_decode(credentials_test_b64url_decode($parts[1]), true);

	expect($header)->toBe(array('alg' => 'RS256', 'typ' => 'JWT'))
		->and($payload)->toBe($claims);

	$signature = credentials_test_b64url_decode($parts[2]);
	$verified  = openssl_verify($parts[0] . '.' . $parts[1], $signature, $public, OPENSSL_ALGO_SHA256);

	expect($verified)->toBe(1);
});

it('reports an error for an unreadable private key', function () {
	list($jwt, $error) = GcpSecretManagerProvider::signJwt(array('iss' => 'x'), 'not-a-key');

	expect($jwt)->toBeNull()
		->and($error)->not->toBe('');
});
