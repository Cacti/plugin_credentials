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
 * Regression coverage for the AWS ECS/EKS container credentials endpoint
 * allowlist. The full-URI source may only be an HTTPS endpoint or plain HTTP to
 * a genuine loopback/link-local address, so a crafted host cannot capture the
 * container authorization token. Exercised through reflection as the method is
 * an internal guard.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

function credentials_test_aws_allowed_uri(string $uri): bool {
	$method = new ReflectionMethod(AwsSecretsManagerProvider::class, 'allowedContainerUri');
	$method->setAccessible(true);

	return (bool) $method->invoke(new AwsSecretsManagerProvider(), $uri);
}

it('accepts HTTPS and genuine loopback or link-local container endpoints', function () {
	expect(credentials_test_aws_allowed_uri('https://example.com/creds'))->toBeTrue()
		->and(credentials_test_aws_allowed_uri('http://127.0.0.1/creds'))->toBeTrue()
		->and(credentials_test_aws_allowed_uri('http://127.0.0.53/creds'))->toBeTrue()
		->and(credentials_test_aws_allowed_uri('http://localhost/creds'))->toBeTrue()
		->and(credentials_test_aws_allowed_uri('http://[::1]/creds'))->toBeTrue()
		->and(credentials_test_aws_allowed_uri('http://169.254.170.2/v2/credentials'))->toBeTrue()
		->and(credentials_test_aws_allowed_uri('http://[fd00:ec2::23]/credentials'))->toBeTrue();
});

it('rejects public hosts, 127-prefixed DNS names and non-http schemes', function () {
	expect(credentials_test_aws_allowed_uri('http://127.attacker.example/creds'))->toBeFalse()
		->and(credentials_test_aws_allowed_uri('http://evil.example/creds'))->toBeFalse()
		->and(credentials_test_aws_allowed_uri('http://169.254.169.254/creds'))->toBeFalse()
		->and(credentials_test_aws_allowed_uri('ftp://127.0.0.1/creds'))->toBeFalse()
		->and(credentials_test_aws_allowed_uri('not a url'))->toBeFalse();
});
