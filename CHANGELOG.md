# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-05-18

### Breaking changes

- Removed `cache_ttl` config key and `IAM_AUTH_CACHE_TTL` env var. RDS auth tokens are now signed per call instead of cached. SigV4 signing cost is microseconds; the cache complexity did not justify itself.
- Removed `credentials_expiry_buffer` config key and `IAM_AUTH_CREDENTIALS_EXPIRY_BUFFER` env var. AWS SDK's standard `Aws\CacheInterface` semantics now govern credential cache TTL.
- `RdsTokenProvider` constructor now takes a single `CachedCredentialProvider` instead of raw callables. `forceFresh` is implemented by invalidating the provider, not by holding a second binding.
- `InjectsIamToken` trait contract reduced to a single `getTokenProvider(): RdsTokenProvider` requirement. The previous `getCacheStore()` hook is gone; the three built-in connectors (MySQL, MariaDB, Postgres) are updated, any custom connector mixing in the trait must update too.
- Deleted `Hackthebox\IamAuth\AwsCredentialCache`. Replaced by `Hackthebox\IamAuth\Cache\AwsCredentialCacheStore` (implements `Aws\CacheInterface`) and `Hackthebox\IamAuth\Cache\CachedCredentialProvider` (the wrapping provider with explicit `invalidate()`).

### Added

- `Aws\CacheInterface` integration: credential caching now uses the AWS SDK's standard extension point. Cached credentials are shared across all AWS SDK clients in the host application (S3, SQS, SES, OpenSearch, etc.), not just RDS.
- `CachedCredentialProvider`: owns the per-request memo and the cross-request store, exposes a public `invalidate()`, and serves `credentialSnapshot()` for observability. Replaces the two-binding (cached + fresh) workaround that earlier rc had to use because `CredentialProvider::memoize` has no invalidation hook.
- Connector-layer single-retry on auth rejection (SQLSTATE 28 / native 1045). Invalidates the provider, mints a fresh token (which also repopulates the store so sibling workers benefit), retries once.
- `iam-auth.rds-auth-rejected-retry-failed` observability channel for the genuinely-residual case (retry also rejected).
- README "Known upstream limitations" section documenting AWS SDK and Pod Identity Agent gaps the package consciously does not work around.

### Removed

- Token cache (`RdsTokenProvider` no longer caches signed tokens).
- `sig_kid` fingerprint machinery (the token cache it served is gone).
- SDK singleton rebuild in `IamAuthServiceProvider`. v3 injects credentials via `config('aws.credentials')` without replacing the singleton, preserving any handlers/middleware added by other packages.
- Boot-time `credentials_expiry_buffer` validator.
- The `iam-auth.credential-provider` and `iam-auth.credential-provider-fresh` container bindings. Use `Hackthebox\IamAuth\Cache\CachedCredentialProvider::class` instead.

### Fixed

- AWS SDK singleton no longer loses other-package customizations (#4).
- All AWS SDK clients in the host app now share cached credentials (#3).
- `credential_provider=ecs` (and any other invokable-class base provider) no longer crashes on construction. The base provider is wrapped in a closure so both `Closure` and invokable-class returns from `CredentialProvider::*` factories work.
- IAM connectors now route the PDO instantiation through `parent::createConnection`, preserving Laravel's `tryAgainIfCausedByLostConnection` wrapper. The earlier `createPdoConnection` seam silently bypassed that retry layer.
- The auth-rejection retry now repopulates the cross-request store on success, so sibling workers no longer thunder the credential agent during rotation.
- `forceFresh=true` reliably bypasses caching for `credential_provider=default`, which previously was undermined by the SDK's internal `memoize` wrapping inside `defaultProvider()`.

## [2.0.0] - 2026-03-26

### Added
- AWS credential caching for PHP-FPM environments (APCu-first strategy)
- Cached SDK credentials benefit all AWS services (S3, SQS, SES, etc.)
- `cache_store` now also caches resolved AWS SDK credentials (separate cache keys and TTLs)
- Integration with `aws/aws-sdk-php-laravel`: extends the SDK singleton with cached credentials
- `credential_provider` config now applies to all AWS SDK operations, not just RDS

### Changed
- Renamed package from `hackthebox/laravel-rds-iam-auth` to `hackthebox/laravel-iam-auth`
- Namespace changed from `Hackthebox\RdsIamAuth` to `Hackthebox\IamAuth`
- Config file renamed from `rds-iam-auth.php` to `iam-auth.php`
- Environment variables renamed from `RDS_IAM_*` to `IAM_AUTH_*`
- Class names updated (e.g. `RdsIamMySqlConnector` to `IamMySqlConnector`)

### Migration from v1.x
1. Update composer.json: `hackthebox/laravel-rds-iam-auth` to `hackthebox/laravel-iam-auth`
2. Rename published config: `config/rds-iam-auth.php` to `config/iam-auth.php`
3. Update env vars: `RDS_IAM_*` to `IAM_AUTH_*`
4. If referencing classes directly, update namespace from `Hackthebox\RdsIamAuth` to `Hackthebox\IamAuth`

## [1.1.0] - 2026-03-20

### Added
- Configurable AWS credential provider via `credential_provider` config / `RDS_IAM_CREDENTIAL_PROVIDER` env var
- Supported providers: `default`, `environment`, `ecs`, `web_identity`, `instance_profile`, `sso`, `ini`

## [1.0.2] - 2026-03-06

### Fixed

- Fix bundled SSL CA path resolution when config file is published to the application's `config/` directory (`__DIR__` resolved to the wrong location)

## [1.0.1] - 2026-03-06

### Fixed

- Enable `MYSQL_ATTR_SSL_VERIFY_SERVER_CERT` on MySQL and MariaDB connectors to verify server identity, matching PostgreSQL's `verify-full` posture
- Validate PostgreSQL `sslmode` is at least `verify-ca`, rejecting insecure values like `prefer` or `disable`
- Validate port is within 1–65535 range to prevent nonsensical port 0
- Use `AWS_DEFAULT_REGION` consistently in README examples to match the package config fallback chain

## [1.0.0] - 2026-03-06

### Added

- RDS IAM authentication connectors for MySQL, MariaDB, and PostgreSQL
- Automatic IAM auth token generation via AWS SDK when `use_iam_auth` is enabled on a database connection
- Token caching via APCu (preferred) or configurable Laravel cache store
- Circular dependency detection for `database` and `dynamodb` cache stores
- Bundled AWS RDS global CA certificate (`global-bundle.pem`)
- Input validation with clear error messages for missing `host`, `username`, or `region`
- Error handling on token generation with actionable `RuntimeException` context
- PostgreSQL `sslmode` enforced to `verify-full` by default via `pgsql_sslmode` package config
- PHPStan static analysis at level 6 with Larastan
- Support for PHP 8.2, 8.3, and 8.4
- Support for Laravel 11 and 12

[Unreleased]: https://github.com/hackthebox/laravel-iam-auth/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/hackthebox/laravel-iam-auth/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/hackthebox/laravel-iam-auth/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/hackthebox/laravel-iam-auth/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/hackthebox/laravel-iam-auth/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/hackthebox/laravel-iam-auth/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/hackthebox/laravel-iam-auth/releases/tag/v1.0.0
