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
 * Contract implemented by every external secret-store driver (HashiCorp Vault,
 * AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, CyberArk Conjur).
 *
 * A driver is a stateless strategy: all per-connection state (endpoint, auth,
 * TLS settings) is supplied by the caller as a decrypted $config array sourced
 * from a credential_providers row. The plugin resolves a credential's secret
 * field at poll time by handing the driver the field's stored reference and the
 * provider instance config; the driver performs the network lookup and returns
 * the plaintext secret. Drivers never touch the Cacti database directly and
 * never persist state, so multiple provider instances of the same type can run
 * side by side.
 */
interface CredentialProvider {
	/**
	 * Stable, lowercase type code persisted in credential_providers.type.
	 *
	 * @return string
	 */
	public function type(): string;

	/**
	 * Human-readable driver name shown in the provider type selector.
	 *
	 * @return string
	 */
	public function label(): string;

	/**
	 * One-line description of the driver shown on the provider edit form.
	 *
	 * @return string
	 */
	public function description(): string;

	/**
	 * The connection/auth fields for a provider instance of this type, declared
	 * with the same attribute shape the credential type registry uses
	 * (friendly_name, method, description, secret, required, default, array,
	 * long, max_length). Fields flagged 'secret' are encrypted with the Cacti
	 * core secret functions before storage.
	 *
	 * @return array
	 */
	public function configFields(): array;

	/**
	 * Label for the per-credential-field reference input shown when a credential
	 * is backed by a provider of this type (for example 'Secret Path').
	 *
	 * @return string
	 */
	public function referenceLabel(): string;

	/**
	 * Help text describing the reference syntax this driver expects, including
	 * the optional '#json_key' selector shared by every driver.
	 *
	 * @return string
	 */
	public function referenceHint(): string;

	/**
	 * Verify connectivity and authentication for a provider instance.
	 *
	 * @param array $config The decrypted provider configuration.
	 *
	 * @return array A [bool ok, string message] pair. The message is safe to
	 *               display and never contains a resolved secret value.
	 */
	public function test(array $config): array;

	/**
	 * Resolve a single secret reference to its plaintext value.
	 *
	 * @param array  $config    The decrypted provider configuration.
	 * @param string $reference The credential field's stored reference.
	 *
	 * @return array A [bool ok, string|null value, string error] triple. On
	 *               success value holds the plaintext; on failure value is null
	 *               and error carries a non-sensitive diagnostic.
	 */
	public function resolve(array $config, string $reference): array;
}
