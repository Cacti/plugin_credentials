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
 * AWS Secrets Manager driver. Calls the GetSecretValue API, signing the request
 * with AWS Signature Version 4. Credentials come either from static access keys
 * stored on the provider instance, or - when 'Use Instance Role' is enabled -
 * from the EC2/ECS instance metadata service (IMDSv2) at resolve time. A
 * reference is the secret id or name, with an optional '#key' selecting a field
 * from a JSON secret, for example 'prod/db/credentials#password'.
 *
 * The Signature Version 4 routine is implemented as pure static helpers so it
 * can be verified against the published AWS test vectors without a network.
 */
class AwsSecretsManagerProvider extends AbstractProvider {
	public function type(): string {
		return 'aws';
	}

	public function label(): string {
		return __('AWS Secrets Manager', 'credentials');
	}

	public function description(): string {
		return __('Resolve secrets from AWS Secrets Manager using IAM access keys or an EC2/ECS instance role.', 'credentials');
	}

	public function referenceLabel(): string {
		return __('Secret Id or Name', 'credentials');
	}

	public function referenceHint(): string {
		return __('An AWS Secrets Manager secret id or name, optionally with \'#key\' to select a field from a JSON secret, for example \'prod/snmp#community\'.', 'credentials');
	}

	public function configFields(): array {
		return array(
			'region' => array(
				'friendly_name' => __('Region', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The AWS region hosting the secrets, for example us-east-1.', 'credentials'),
				'required'      => true,
				'max_length'    => 64,
			),
			'use_instance_role' => array(
				'friendly_name' => __('Use Instance Role', 'credentials'),
				'method'        => 'checkbox',
				'description'   => __('Obtain temporary credentials from the EC2/ECS instance metadata service instead of static keys.', 'credentials'),
				'default'       => '',
			),
			'access_key_id' => array(
				'friendly_name' => __('Access Key Id', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The IAM access key id used when not using an instance role.', 'credentials'),
				'max_length'    => 128,
			),
			'secret_access_key' => array(
				'friendly_name' => __('Secret Access Key', 'credentials'),
				'method'        => 'textbox_password',
				'description'   => __('The IAM secret access key. Stored encrypted.', 'credentials'),
				'secret'        => true,
				'max_length'    => 255,
			),
			'session_token' => array(
				'friendly_name' => __('Session Token', 'credentials'),
				'method'        => 'textbox_password',
				'description'   => __('An optional STS session token for temporary static credentials. Stored encrypted.', 'credentials'),
				'secret'        => true,
				'max_length'    => 2048,
			),
			'endpoint' => array(
				'friendly_name' => __('Endpoint Override', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('An optional endpoint override (for VPC endpoints or testing). Defaults to the public AWS endpoint for the region.', 'credentials'),
				'max_length'    => 255,
			),
			'timeout' => array(
				'friendly_name' => __('Timeout (seconds)', 'credentials'),
				'method'        => 'textbox',
				'description'   => __('The network timeout for AWS requests.', 'credentials'),
				'default'       => '15',
				'max_length'    => 4,
			),
		);
	}

	public function test(array $config): array {
		if ($this->cfg($config, 'region') === '') {
			return array(false, __('An AWS region is required.', 'credentials'));
		}

		list($creds, $err) = $this->credentials($config);

		if ($creds === null) {
			return array(false, $err);
		}

		/* ListSecrets with a page size of 1 proves auth and connectivity without
		 * requiring knowledge of a specific secret name */
		list($ok, $status, $body, $herr) = $this->callApi($config, $creds, 'secretsmanager.ListSecrets', array('MaxResults' => 1));

		if (!$ok) {
			return array(false, $herr);
		}

		if ($status >= 200 && $status < 300) {
			return array(true, __('Successfully authenticated to AWS Secrets Manager.', 'credentials'));
		}

		return array(false, $this->apiError($status, $body));
	}

	public function resolve(array $config, string $reference): array {
		list($secret_id, $json_key) = $this->splitReference($reference);

		if ($secret_id === '') {
			return array(false, null, __('An AWS secret id is required.', 'credentials'));
		}

		list($creds, $err) = $this->credentials($config);

		if ($creds === null) {
			return array(false, null, $err);
		}

		list($ok, $status, $body, $herr) = $this->callApi($config, $creds, 'secretsmanager.GetSecretValue', array('SecretId' => $secret_id));

		if (!$ok) {
			return array(false, null, $herr);
		}

		if ($status < 200 || $status >= 300) {
			return array(false, null, $this->apiError($status, $body));
		}

		$decoded = $this->decodeJson($body);

		if ($decoded === null) {
			return array(false, null, __('AWS returned an unexpected response reading the secret.', 'credentials'));
		}

		if (isset($decoded['SecretString'])) {
			$payload = (string) $decoded['SecretString'];
		} elseif (isset($decoded['SecretBinary'])) {
			$payload = (string) base64_decode((string) $decoded['SecretBinary'], true);
		} else {
			return array(false, null, __('The AWS secret has no retrievable value.', 'credentials'));
		}

		return $this->selectValue($payload, $json_key);
	}

	/**
	 * Resolve the signing credentials to use, fetching temporary credentials
	 * from the instance metadata service when the instance-role option is set.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [array|null credentials, string error] pair. Credentials
	 *               is a map of key/secret/token on success.
	 */
	private function credentials(array $config): array {
		if ($this->flag($config, 'use_instance_role', false)) {
			return $this->instanceCredentials($config);
		}

		$key    = (string) $this->cfg($config, 'access_key_id');
		$secret = (string) $this->cfg($config, 'secret_access_key');

		if ($key === '' || $secret === '') {
			return array(null, __('An access key id and secret access key are required unless an instance role is used.', 'credentials'));
		}

		return array(
			array('key' => $key, 'secret' => $secret, 'token' => (string) $this->cfg($config, 'session_token')),
			'',
		);
	}

	/**
	 * Fetch temporary credentials for the task/instance role. The ECS/EKS
	 * container credentials endpoint (used by Fargate and ECS task roles) is
	 * preferred when the standard AWS environment variables are present; only
	 * when no container source is configured does this fall back to the EC2
	 * instance metadata service. Not reachable off AWS; errors are surfaced
	 * rather than thrown.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [array|null credentials, string error] pair.
	 */
	private function instanceCredentials(array $config): array {
		$relative = getenv('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI');

		if ($relative !== false && $relative !== '') {
			/* the relative URI is a path on the fixed ECS link-local endpoint;
			 * validate the assembled URL so a value such as '@attacker.example/'
			 * cannot turn 169.254.170.2 into userinfo and send the token offbox */
			$url = 'http://169.254.170.2' . $relative;

			if (!$this->allowedContainerUri($url)) {
				return array(null, __('The ECS relative credentials URI is not valid.', 'credentials'));
			}

			return $this->containerCredentials($config, $url);
		}

		$full = getenv('AWS_CONTAINER_CREDENTIALS_FULL_URI');

		if ($full !== false && $full !== '') {
			if (!$this->allowedContainerUri($full)) {
				return array(null, __('The configured ECS credentials endpoint is not an allowed address.', 'credentials'));
			}

			return $this->containerCredentials($config, $full);
		}

		return $this->ec2InstanceCredentials($config);
	}

	/**
	 * Read task-role credentials from the ECS/EKS container credentials endpoint,
	 * sending the container authorization token when one is configured.
	 *
	 * @param array  $config The decrypted provider configuration.
	 * @param string $url    The resolved container credentials URL.
	 *
	 * @return array A [array|null credentials, string error] pair.
	 */
	private function containerCredentials(array $config, string $url): array {
		$headers = array('Accept: application/json');
		$token   = $this->containerAuthToken();

		if ($token !== '') {
			$headers[] = 'Authorization: ' . $token;
		}

		list($status, $body, $err) = $this->http($config, 'GET', $url, $headers);

		if ($status === null || $status < 200 || $status >= 300) {
			return array(null, __('Unable to read ECS task role credentials.', 'credentials'));
		}

		$decoded = $this->decodeJson($body);

		if ($decoded === null || !isset($decoded['AccessKeyId'], $decoded['SecretAccessKey'])) {
			return array(null, __('The ECS credentials endpoint returned no usable credentials.', 'credentials'));
		}

		return array(
			array(
				'key'    => (string) $decoded['AccessKeyId'],
				'secret' => (string) $decoded['SecretAccessKey'],
				'token'  => isset($decoded['Token']) ? (string) $decoded['Token'] : '',
			),
			'',
		);
	}

	/**
	 * The ECS container authorization token, read from a token file when one is
	 * configured, otherwise from the token environment variable.
	 *
	 * @return string The token value, or '' when none is configured.
	 */
	private function containerAuthToken(): string {
		$file = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE');

		if ($file !== false && $file !== '' && is_readable($file)) {
			return trim((string) file_get_contents($file));
		}

		$token = getenv('AWS_CONTAINER_AUTHORIZATION_TOKEN');

		return $token !== false ? trim((string) $token) : '';
	}

	/**
	 * Whether a full container credentials URI is an allowed target. Mirrors the
	 * AWS SDK rule: HTTPS is always allowed; plain HTTP only to a loopback or the
	 * ECS/EKS link-local addresses, so a crafted endpoint cannot exfiltrate the
	 * authorization token.
	 *
	 * @param string $uri The configured full URI.
	 *
	 * @return bool
	 */
	private function allowedContainerUri(string $uri): bool {
		$parts = parse_url($uri);

		if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
			return false;
		}

		$scheme = strtolower($parts['scheme']);

		if ($scheme === 'https') {
			return true;
		}

		if ($scheme !== 'http') {
			return false;
		}

		/* parse_url keeps the brackets around an IPv6 literal; strip them so the
		 * bare address can be compared (for example '[::1]' -> '::1') */
		$host = strtolower(trim((string) $parts['host'], '[]'));

		$allowed = array('localhost', '127.0.0.1', '::1', '169.254.170.2', '169.254.170.23', 'fd00:ec2::23');

		if (in_array($host, $allowed, true)) {
			return true;
		}

		/* any 127.0.0.0/8 loopback, but only as a real IPv4 literal - never a DNS
		 * name such as '127.attacker.example' that merely starts with '127.' */
		return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && strncmp($host, '127.', 4) === 0;
	}

	/**
	 * Fetch temporary credentials from the EC2 instance metadata service using
	 * IMDSv2 (token-protected).
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [array|null credentials, string error] pair.
	 */
	private function ec2InstanceCredentials(array $config): array {
		$imds = 'http://169.254.169.254';

		list($status, $token, $err) = $this->http($config, 'PUT', $imds . '/latest/api/token', array('X-aws-ec2-metadata-token-ttl-seconds: 60'));

		if ($status === null || $status < 200 || $status >= 300 || trim($token) === '') {
			return array(null, __('Unable to obtain an instance metadata token; is Cacti running on an AWS instance with a role?', 'credentials'));
		}

		$hdr = array('X-aws-ec2-metadata-token: ' . trim($token));

		list($rstatus, $role, $rerr) = $this->http($config, 'GET', $imds . '/latest/meta-data/iam/security-credentials/', $hdr);

		if ($rstatus === null || $rstatus < 200 || $rstatus >= 300 || trim($role) === '') {
			return array(null, __('No IAM role is attached to this instance.', 'credentials'));
		}

		$role = trim(strtok($role, "\n"));

		list($cstatus, $cbody, $cerr) = $this->http($config, 'GET', $imds . '/latest/meta-data/iam/security-credentials/' . rawurlencode($role), $hdr);

		if ($cstatus === null || $cstatus < 200 || $cstatus >= 300) {
			return array(null, __('Unable to read instance role credentials.', 'credentials'));
		}

		$decoded = $this->decodeJson($cbody);

		if ($decoded === null || !isset($decoded['AccessKeyId'], $decoded['SecretAccessKey'])) {
			return array(null, __('The instance metadata service returned no usable credentials.', 'credentials'));
		}

		return array(
			array(
				'key'    => (string) $decoded['AccessKeyId'],
				'secret' => (string) $decoded['SecretAccessKey'],
				'token'  => isset($decoded['Token']) ? (string) $decoded['Token'] : '',
			),
			'',
		);
	}

	/**
	 * Build, sign and send a Secrets Manager JSON API call.
	 *
	 * @param array  $config  The decrypted provider configuration.
	 * @param array  $creds   The signing credentials (key/secret/token).
	 * @param string $target  The X-Amz-Target value, including the API action.
	 * @param array  $payload The request payload.
	 *
	 * @return array A [bool ok, int|null status, string body, string error] tuple.
	 */
	private function callApi(array $config, array $creds, string $target, array $payload): array {
		$region = (string) $this->cfg($config, 'region');
		$host   = $this->host($config, $region);
		$body   = json_encode($payload);

		if ($body === false) {
			return array(false, null, '', __('Unable to encode the AWS request.', 'credentials'));
		}

		$amzdate   = gmdate('Ymd\THis\Z');
		$datestamp = gmdate('Ymd');

		$headers = array(
			'content-type' => 'application/x-amz-json-1.1',
			'host'         => $host,
			'x-amz-date'   => $amzdate,
			'x-amz-target' => $target,
		);

		if (!empty($creds['token'])) {
			$headers['x-amz-security-token'] = $creds['token'];
		}

		$authorization = self::sign('secretsmanager', $region, 'POST', '/', '', $headers, $body, $creds['key'], $creds['secret'], $amzdate, $datestamp);

		$header_lines = array('Authorization: ' . $authorization);

		foreach ($headers as $name => $value) {
			$header_lines[] = $this->headerName($name) . ': ' . $value;
		}

		$scheme   = 'https://';
		$endpoint = (string) $this->cfg($config, 'endpoint');
		$url      = $endpoint !== '' ? rtrim($endpoint, '/') . '/' : $scheme . $host . '/';

		list($status, $resp, $err) = $this->http($config, 'POST', $url, $header_lines, $body);

		if ($status === null) {
			return array(false, null, '', $err);
		}

		return array(true, $status, $resp, '');
	}

	/**
	 * The Secrets Manager host for a region, honouring an endpoint override.
	 *
	 * @param array  $config The decrypted provider configuration.
	 * @param string $region The AWS region.
	 *
	 * @return string
	 */
	private function host(array $config, string $region): string {
		$endpoint = (string) $this->cfg($config, 'endpoint');

		if ($endpoint !== '') {
			return (string) parse_url($endpoint, PHP_URL_HOST);
		}

		return 'secretsmanager.' . $region . '.amazonaws.com';
	}

	/**
	 * Render a lowercase canonical header name back to conventional casing for
	 * the wire. AWS accepts any casing; this keeps the request readable.
	 *
	 * @param string $name The lowercase header name.
	 *
	 * @return string
	 */
	private function headerName(string $name): string {
		$map = array(
			'content-type'         => 'Content-Type',
			'host'                 => 'Host',
			'x-amz-date'           => 'X-Amz-Date',
			'x-amz-target'         => 'X-Amz-Target',
			'x-amz-security-token' => 'X-Amz-Security-Token',
		);

		return isset($map[$name]) ? $map[$name] : $name;
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

		if (is_array($decoded) && isset($decoded['__type'])) {
			$type = (string) $decoded['__type'];
			$type = substr($type, (int) strrpos($type, '#') + 1);

			return __('AWS Secrets Manager error: %s (HTTP %d).', $type, $status, 'credentials');
		}

		return __('AWS Secrets Manager returned HTTP %d.', $status, 'credentials');
	}

	/**
	 * Produce the SigV4 Authorization header value for a request. Pure and
	 * deterministic given its inputs; verified against the AWS Signature Version
	 * 4 test suite.
	 *
	 * @param string $service   The AWS service name.
	 * @param string $region    The AWS region.
	 * @param string $method    The HTTP method.
	 * @param string $uri       The canonical URI path.
	 * @param string $query     The canonical query string.
	 * @param array  $headers   Lowercase header name => value map (must include host and x-amz-date).
	 * @param string $body      The request body.
	 * @param string $accessKey The access key id.
	 * @param string $secretKey The secret access key.
	 * @param string $amzdate   The ISO8601 basic timestamp (yyyymmddThhmmssZ).
	 * @param string $datestamp The yyyymmdd date stamp.
	 *
	 * @return string The full Authorization header value.
	 */
	public static function sign(string $service, string $region, string $method, string $uri, string $query, array $headers, string $body, string $accessKey, string $secretKey, string $amzdate, string $datestamp): string {
		ksort($headers);

		$canonical_headers = '';
		$signed_parts      = array();

		foreach ($headers as $name => $value) {
			$name                = strtolower($name);
			$canonical_headers  .= $name . ':' . self::trimHeaderValue((string) $value) . "\n";
			$signed_parts[]      = $name;
		}

		$signed_headers = implode(';', $signed_parts);

		$canonical_request = $method . "\n"
			. $uri . "\n"
			. $query . "\n"
			. $canonical_headers . "\n"
			. $signed_headers . "\n"
			. hash('sha256', $body);

		$scope = $datestamp . '/' . $region . '/' . $service . '/aws4_request';

		$string_to_sign = 'AWS4-HMAC-SHA256' . "\n"
			. $amzdate . "\n"
			. $scope . "\n"
			. hash('sha256', $canonical_request);

		$signing_key = self::signingKey($secretKey, $datestamp, $region, $service);
		$signature   = hash_hmac('sha256', $string_to_sign, $signing_key);

		return 'AWS4-HMAC-SHA256 '
			. 'Credential=' . $accessKey . '/' . $scope . ', '
			. 'SignedHeaders=' . $signed_headers . ', '
			. 'Signature=' . $signature;
	}

	/**
	 * Derive the SigV4 signing key.
	 *
	 * @param string $secretKey The secret access key.
	 * @param string $datestamp The yyyymmdd date stamp.
	 * @param string $region    The AWS region.
	 * @param string $service   The AWS service name.
	 *
	 * @return string The raw (binary) signing key.
	 */
	public static function signingKey(string $secretKey, string $datestamp, string $region, string $service): string {
		$kdate    = hash_hmac('sha256', $datestamp, 'AWS4' . $secretKey, true);
		$kregion  = hash_hmac('sha256', $region, $kdate, true);
		$kservice = hash_hmac('sha256', $service, $kregion, true);

		return hash_hmac('sha256', 'aws4_request', $kservice, true);
	}

	/**
	 * Collapse internal whitespace in a header value per the SigV4 trimall rule.
	 *
	 * @param string $value The raw header value.
	 *
	 * @return string
	 */
	private static function trimHeaderValue(string $value): string {
		return trim((string) preg_replace('/\s+/', ' ', $value));
	}
}
