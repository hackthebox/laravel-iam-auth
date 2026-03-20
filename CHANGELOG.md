# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-03-20

### Added
- AWS credential caching for PHP-FPM environments (APCu-first strategy)
- Cached SDK credentials benefit all AWS services (S3, SQS, SES, etc.)
- New `credential_cache` config option
- Configurable AWS credential provider via `credential_provider` config / `IAM_AUTH_CREDENTIAL_PROVIDER` env var

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

[Unreleased]: https://github.com/hackthebox/laravel-iam-auth/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/hackthebox/laravel-iam-auth/compare/v1.0.2...v2.0.0
[1.0.2]: https://github.com/hackthebox/laravel-iam-auth/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/hackthebox/laravel-iam-auth/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/hackthebox/laravel-iam-auth/releases/tag/v1.0.0
