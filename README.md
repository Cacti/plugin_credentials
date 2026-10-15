# plugin_credentials

A plugin for building and managing credentials to be used in Cacti.

The Credentials plugin provides a centralized, **encrypted** credential store
covering the credential types commonly used by network monitoring and fault
management systems, grouped into three tiers:

### Tier 1 — Core polling
- **SNMP v1/v2c Community** — version + read/write community strings
- **SNMP v3 (USM)** — security name, auth protocol/passphrase, privacy
  protocol/passphrase, context, engine id
- **Username / Password** — a reusable generic user/password
- **SSH** — username with password *or* private key (+ passphrase) and port

### Tier 2 — Modern API / cloud
- **Bearer / API Token**
- **API Key** (header or query parameter)
- **GitHub Personal Access Token**
- **OAuth 2.0 Client Credentials**
- **HTTP Basic Auth**

### Tier 3 — Extended device coverage
- **WMI (Windows)**
- **IPMI / Redfish (BMC)**
- **Database** (MySQL/MariaDB, PostgreSQL, MS SQL, Oracle)
- **VMware / vCenter**
- **TLS Client Certificate**

## How it works

- Each credential is stored in the `credentials` table with `name`,
  `description`, `type`, `provider_id`, `user_id`, `enabled`, `properties`,
  `create_date` and `last_updated` columns (the two dates are SQL timestamps).
  `provider_id` is `0` for the local encrypted store, or the id of a
  `credential_providers` row for an external provider.
- The type-specific attributes are rendered on the edit form using the Cacti
  Form API — every field carries its own tooltip — and are stored as JSON in the
  `properties` column.
- **All sensitive fields are encrypted** with the Cacti core secret functions
  (`cacti_encrypt_secret()` / `cacti_encrypt_secret_with_key()`). Secrets are
  never rendered back to the browser; when a secret is already stored the form
  states so and leaving the field blank keeps the existing value.
- Switching the **Credential Type** of an already-created credential raises a
  jQueryUI confirmation dialog warning that the stored type-specific values will
  be discarded on save.

## External secret providers

In addition to the built-in **local encrypted database**, a credential's secret
fields can be sourced at poll time from an external secret store. The following
providers ship with the plugin:

- **HashiCorp Vault** — KV v1/v2 engines; Token or AppRole authentication
- **AWS Secrets Manager** — IAM access keys or an EC2/ECS instance role
  (requests are signed with AWS Signature Version 4)
- **Azure Key Vault** — Entra ID service principal or Managed Identity
- **Google Cloud Secret Manager** — service account key (signed JWT) or the
  instance service account
- **CyberArk Conjur** — host/user identity with an API key

### How provider-backed credentials work

- Provider **instances** are configured on the **Secret Providers** page and
  stored in the `credential_providers` table. Each instance's own connection
  secrets (tokens, keys, client secrets) are encrypted with the same Cacti core
  secret functions used for local credentials.
- You can configure **any number of providers**, including several instances of
  the same type (for example a production and a staging Vault), and choose a
  different provider per credential — or keep some credentials local.
- When a credential selects a provider, each secret field stores a
  **non-sensitive reference** (a path/locator) instead of the secret. The
  reference supports an optional `#key` selector to pull a single field out of a
  JSON secret (for example `network/snmp#community`), including dotted paths into
  nested JSON.
- `credentials_get($id)` transparently resolves references through the provider
  driver, returning live plaintext to the caller exactly as it does for locally
  stored secrets. Resolution is cached per request, and a provider failure
  **fails closed** (the secret resolves to `false`) and is logged without
  leaking the secret value.
- Each provider instance offers a **Test Connection** self-check on its edit
  form that verifies connectivity and authentication.

### Adding another provider

Providers are pluggable: implement the `CredentialProvider` interface (see
`includes/providers/`) and register the driver in
`credentials_provider_registry()`. Nothing in the storage or UI layer needs to
change — the new type automatically appears in the provider type selector and
its configuration fields render from the driver's `configFields()`.

## Access control

Access to `credentials.php` and `credential_providers.php` is gated by the core
**Users/Groups** permission — the same permission that governs Users and User
Groups administration. The **Credentials** and **Secret Providers** Console
picks appear directly below **User Domains** on Cacti 1.2.x and below **Login
Providers** on develop / 1.3+.

## Cacti version compatibility

The plugin targets Cacti **1.2.29+**. Secret encryption uses Cacti core's
AES‑256‑GCM helpers (`cacti_encrypt_secret()` / `cacti_encrypt_secret_with_key()`
/ `cacti_secret_key()` and their decrypt counterparts), which were added to the
`1.2.x` branch in **1.2.32**.

To keep the credential store usable on the supported 1.2.29–1.2.31 releases that
predate those APIs, `includes/functions.php` performs a `cacti_version_compare()`
check and, **only when the running Cacti is older than 1.2.32**, defines a
byte‑for‑byte compatible copy of the core secret functions (sourced from the
Cacti `1.2.x` branch). On 1.2.32 and newer, core already provides them and the
plugin uses core's own implementation — the fallback blocks are skipped. In all
cases every secret is encrypted with the same per‑installation
`secret_encryption_key`, so values remain portable across the upgrade boundary.

## Programmatic use

Other Cacti code and plugins can retrieve a ready-to-use credential (with its
secret fields decrypted) via `credentials_get($id)` from
`plugins/credentials/includes/functions.php`.

## Installation

1. Place this plugin in `plugins/credentials` within your Cacti installation.
2. Install and enable it from **Console > Configuration > Plugins**.
3. Open **Console > Configuration > Credentials** to manage credentials.
4. Optionally open **Console > Configuration > Secret Providers** to configure
   external secret stores, then select one as the **Secret Provider** on a
   credential.
