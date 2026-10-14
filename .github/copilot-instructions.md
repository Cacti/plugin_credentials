# GitHub Copilot Instructions

## Priority Guidelines

When generating code for this repository:

1. **Version Compatibility**: This is a Cacti plugin (`credentials`, version 1.0) targeting Cacti 1.2.x (CI matrix PHP 8.2/8.3/8.4).
2. **Context Files**: Prioritize patterns and standards defined in this file and `.github/instructions/php.instructions.md`.
3. **Codebase Patterns**: When context files don't provide specific guidance, scan the codebase for established patterns.
4. **Architectural Consistency**: Maintain the plugin-based architecture extending Cacti core.
5. **Code Quality**: Prioritize security, maintainability, and compatibility — this plugin stores secrets, so encryption and access control are first-class concerns.

## Technology Stack

- **PHP**: Minimum PHP 8.2; write for the lowest version in the CI matrix.
- **Platform**: Cacti Plugin Architecture (Cacti 1.2.x).
- **Database**: MySQL/MariaDB with the InnoDB engine.
- **Crypto**: Cacti core secret functions (`cacti_encrypt_secret()` / `cacti_encrypt_secret_with_key()` and their decrypt counterparts) for all secret-at-rest handling.
- **Key Dependencies**: Cacti core framework (`api_plugin_*`, `db_*`, form/HTML helpers). No plugin-local Composer tree — CI uses Cacti's vendor tree.

## Project Structure

```
credentials/              # Repository root (install to plugins/credentials/ in Cacti)
├── includes/
│   ├── arrays.php         # Credential type registry (fields, methods, tooltips, secret flags)
│   ├── functions.php      # Encryption wrappers, property helpers, credentials_get()
│   └── index.php          # Access protection
├── credentials.php        # Main management page (list + add/edit + save + actions)
├── credentials.js         # Client-side type-switch confirmation dialog
├── setup.php              # Plugin install/uninstall/upgrade hooks, menu + realm gating
├── locales/po/cacti.pot   # gettext template (Weblate owns the .po/.mo catalogs)
├── manifest.json          # Upgrade-time prune manifest (validated by CI)
├── INFO                   # Plugin metadata (name, version, compat)
├── README.md              # Feature overview, installation and usage
└── CHANGELOG              # Version history
```

## Naming Conventions

### Function Names
- Cacti plugin hook functions MUST be prefixed `plugin_credentials_` (e.g. `plugin_credentials_install()`).
- Internal/display helpers MUST be prefixed `credentials_` (e.g. `credentials_config_arrays()`, `credentials_encrypt()`).
- Match the existing prefix of the function you edit; do not introduce a third scheme.

### Database Table
This plugin deliberately uses a single, unprefixed table named **`credentials`** (not `plugin_credentials_*`). This is an intentional product decision for a shared, cross-plugin credential store. Create it with `api_plugin_db_table_create()` so upgrade/uninstall bookkeeping works.

### Variables
- Use snake_case for variables (`$credential`, `$type_options`, `$props`).

## Type Hints

Every function MUST declare parameter and return types. Prefer precise types
(`string`, `array`, `bool`, `int`, `void`, and unions such as `array|false` or
`string|false`). Keep the PHPDoc `@param`/`@return` in sync with the signature.

## Code Style

- **Tabs** (not spaces) for indentation; opening brace on the same line; space after control keywords.
- Prefer single-quoted strings; short arrays (`[]`) are acceptable but match surrounding code.
- ALL PHP files MUST carry the standard Cacti GPL v2 header block.

## Security Standards

### Secrets
- Every sensitive field is encrypted with the Cacti core secret functions before it is written to `credentials.properties`. Confirm `credentials_encryption_available()` first; fail closed if it is false.
- NEVER render a stored secret back to the browser. The edit form shows a "a value is stored" hint and keeps the existing value when the field is left blank.
- NEVER log a secret, token, passphrase, or decrypted value.

### SQL
- ALWAYS use prepared statements (`db_fetch_row_prepared()`, `db_execute_prepared()`, ...). Never concatenate request data into SQL. Validate sort columns/identifiers against an allowlist.

### Input, authorization, output
- Use `get_filter_request_var()` / `get_nfilter_request_var()` / `isset_request_var()`; never read `$_GET`/`$_POST` directly.
- Access to `credentials.php` is gated on the core **Users/Groups** realm (realm id 1) via `$user_auth_realm_filenames['credentials.php'] = 1` in the `config_arrays` hook; `include/auth.php` enforces it. Keep that gating intact.
- Escape at output with `html_escape()` / `__esc()` for the exact context.
- Protect state-changing actions with Cacti's CSRF/POST handling.

## Plugin Architecture

### Hooks
Register hooks in `plugin_credentials_install()` (`setup.php`):

```php
api_plugin_register_hook('credentials', 'config_arrays',        'credentials_config_arrays',        'setup.php');
api_plugin_register_hook('credentials', 'draw_navigation_text', 'credentials_draw_navigation_text', 'setup.php');
api_plugin_register_hook('credentials', 'page_head',            'credentials_page_head',            'setup.php');
```

### Menu placement
The `config_arrays` hook inserts the **Credentials** Console pick directly below **User Domains** (`user_domains.php`, Cacti 1.2.x) or **Login Providers** (`login_providers.php`, develop/1.3+), rebuilding the Configuration submenu to preserve order, with a Configuration-section fallback.

## Internationalization

- Wrap every user-facing string in `__()` / `__esc()` with the `'credentials'` text domain.
- `locales/po/cacti.pot` is the only translation artifact a PR may add or modify. NEVER commit the per-language `.po`/`.mo` files — Weblate owns them.
- When a PR adds/changes a translatable string, regenerate `locales/po/cacti.pot` (`locales/build_gettext.sh`, run from inside a Cacti checkout) and stage only that file. CI's `tests/bin/check-i18n-pot.php` fails a PR that moves strings without updating the template.

## Testing

- Unit tests use Pest under `tests/` with `tests/bootstrap-unit.php` (which stubs Cacti's global functions, including reversible encryption doubles). Run via `include/vendor/bin/pest --configuration=plugins/credentials/phpunit.xml`.
- `phpunit.xml` scopes Clover coverage to `setup.php`, `includes/arrays.php`, and `includes/functions.php`. Web entry points (`credentials.php`, directory `index.php` guards) are measured through the `tests/bin/patch-coverage.php` allowlist because they cannot be loaded into the isolated unit process.
- CI enforces **100% coverage of the lines a PR changes** in the measured files, so add/extend tests for every production line you touch. Keep each function's branches coverable in a single process (prefer single-return ternaries over two-branch `if`/`else` where a branch depends on process-global state such as `class_exists()`).
- Name tests after behavior, not an issue/GHSA number.

## CI & Dependency Baselines

- Do NOT commit a plugin-local `composer.json`/`composer.lock`, `.phpstan.neon`, or `.php-cs-fixer.php`; the shared CI workflow uses Cacti's own toolchain against this plugin's directory.
- Prefer Cacti's `cacti_sizeof()`/`cacti_count()` wrappers over raw `count()`/`sizeof()`.

## File manifest & upgrade pruning

`manifest.json` lists `tombstones`, `expected` (top-level files/dirs shipped today, directories with a trailing `/`), and `whitelist`. Keep `expected` current — CI's `tests/bin/validate-manifest.php` fails on drift (it ignores `tests/`, `phpunit.xml`, `.git*`, `.md*`, and whitelisted paths). When you move or delete a shipped file, add its old path to `tombstones` and update `expected` in the same change.

## References

- Cacti Plugin Development Guide, Cacti API documentation.
- `.github/instructions/php.instructions.md` for the org-wide PHP contract.
