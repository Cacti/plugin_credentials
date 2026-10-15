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
 * Unit coverage for the AWS Signature Version 4 implementation used by the
 * AWS Secrets Manager driver. The expected values are the published vectors
 * from AWS: the "Deriving the signing key" example (service iam) and the
 * aws4_testsuite "get-vanilla" request (service service).
 *
 * See https://docs.aws.amazon.com/ and the aws-sig-v4-test-suite.
 */

beforeAll(function () {
	require_once __DIR__ . '/../../setup.php';
});

it('derives the documented AWS example signing key', function () {
	$key = AwsSecretsManagerProvider::signingKey(
		'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
		'20150830',
		'us-east-1',
		'iam'
	);

	expect(bin2hex($key))->toBe('c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9');
});

it('produces the aws4_testsuite get-vanilla signature', function () {
	$authorization = AwsSecretsManagerProvider::sign(
		'service',
		'us-east-1',
		'GET',
		'/',
		'',
		array(
			'host'       => 'example.amazonaws.com',
			'x-amz-date' => '20150830T123600Z',
		),
		'',
		'AKIDEXAMPLE',
		'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
		'20150830T123600Z',
		'20150830'
	);

	expect($authorization)
		->toContain('Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request')
		->and($authorization)->toContain('SignedHeaders=host;x-amz-date')
		->and($authorization)->toContain('Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
});

it('sorts signed headers and includes a security token when present', function () {
	$authorization = AwsSecretsManagerProvider::sign(
		'secretsmanager',
		'us-west-2',
		'POST',
		'/',
		'',
		array(
			'x-amz-target'         => 'secretsmanager.GetSecretValue',
			'host'                 => 'secretsmanager.us-west-2.amazonaws.com',
			'content-type'         => 'application/x-amz-json-1.1',
			'x-amz-date'           => '20200101T000000Z',
			'x-amz-security-token' => 'session-token',
		),
		'{"SecretId":"x"}',
		'AKID',
		'secret',
		'20200101T000000Z',
		'20200101'
	);

	expect($authorization)->toContain('SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target');
});
