# Laravel IAM Auth

AWS IAM authentication for Laravel: RDS database connections and SDK credential caching. Designed for EKS workloads using Pod Identity or IRSA — no sidecars, no static credentials.

## Features

- **RDS IAM Auth** — overrides Laravel's MySQL, MariaDB, and PostgreSQL connectors to generate short-lived IAM auth tokens via the AWS SDK when `use_iam_auth` is enabled on a connection.
- **AWS Credential Caching** — caches resolved AWS SDK credentials across PHP-FPM requests (APCu-first), benefiting all AWS SDK calls (S3, SQS, SES, etc.).

## How It Works

This package overrides Laravel's database connectors for MySQL, MariaDB, and PostgreSQL. When `use_iam_auth` is enabled on a connection, the connector generates a short-lived IAM auth token (via the AWS SDK) and uses it as the database password. Tokens are cached via APCu (preferred) or a configurable Laravel cache store to avoid per-request STS calls.

The package does **not** introduce a new database driver. Laravel's `MySqlConnection`, `MariaDbConnection`, and `PostgresConnection` are used as-is.

## Requirements

- PHP >= 8.2
- Laravel 11 or 12
- AWS SDK for PHP >= 3.249 (Pod Identity support)
- APCu extension (recommended for production — caches tokens and credentials across FPM requests)
- RDS instance with IAM authentication enabled
- SSL CA bundle (bundled — override via `IAM_AUTH_SSL_CA_PATH` env if needed)

## Installation

```bash
composer require hackthebox/laravel-iam-auth
```

The service provider is auto-discovered. To publish the config:

```bash
php artisan vendor:publish --tag=iam-auth-config
```

## Configuration

### Database Connection

Add `use_iam_auth` and `region` to your connection in `config/database.php`:

**MySQL / MariaDB:**

```php
'mysql' => [
    'driver' => 'mysql', // or 'mariadb'
    'host' => env('DB_HOST', '127.0.0.1'),
    'port' => env('DB_PORT', '3306'),
    'database' => env('DB_DATABASE', 'forge'),
    'username' => env('DB_USERNAME', 'forge'),
    'password' => env('DB_PASSWORD', ''),
    'use_iam_auth' => env('DB_USE_IAM_AUTH', false),
    'region' => env('AWS_DEFAULT_REGION', 'eu-central-1'),
    'charset' => 'utf8mb4',
    'collation' => 'utf8mb4_unicode_ci',
    'prefix' => '',
    'strict' => true,
    'engine' => null,
],
```

**PostgreSQL:**

```php
'pgsql' => [
    'driver' => 'pgsql',
    'host' => env('DB_HOST', '127.0.0.1'),
    'port' => env('DB_PORT', '5432'),
    'database' => env('DB_DATABASE', 'forge'),
    'username' => env('DB_USERNAME', 'forge'),
    'password' => env('DB_PASSWORD', ''),
    'use_iam_auth' => env('DB_USE_IAM_AUTH', false),
    'region' => env('AWS_DEFAULT_REGION', 'eu-central-1'),
    'charset' => 'utf8',
    'prefix' => '',
    'schema' => 'public',
],
```

When `use_iam_auth` is `false`, the connector behaves identically to Laravel's default — `password` is used as-is.

### Environment Variables

**Production (EKS with Pod Identity):**

```env
DB_USE_IAM_AUTH=true
DB_PASSWORD=
AWS_DEFAULT_REGION=eu-central-1
```

**Local development:**

```env
DB_USE_IAM_AUTH=false
DB_PASSWORD=secret
```

### Package Config

The package config (`config/iam-auth.php`):

| Key | Default | Description |
|---|---|---|
| `region` | `AWS_DEFAULT_REGION` / `AWS_REGION` env | Fallback region when not set on connection |
| `credential_provider` | `default` | AWS credential provider. Override with `IAM_AUTH_CREDENTIAL_PROVIDER` env. Supported: `default`, `environment`, `ecs`, `web_identity`, `instance_profile`, `sso`, `ini`. |
| `cache_store` | `null` | Laravel cache store for caching RDS tokens and AWS credentials when APCu is unavailable. Use `file`, `redis`, `memcached`, etc. **Never** `database` or `dynamodb`. Override with `IAM_AUTH_CACHE_STORE` env. |
| `cache_ttl` | `600` (10 min) | RDS token cache TTL in seconds. Override with `IAM_AUTH_CACHE_TTL` env. |
| `pgsql_sslmode` | `verify-full` | SSL mode for PostgreSQL IAM connections. Override with `IAM_AUTH_PGSQL_SSLMODE` env. |
| `ssl_ca_path` | Bundled `global-bundle.pem` | Path to the RDS CA bundle. Override with `IAM_AUTH_SSL_CA_PATH` env. |

## RDS IAM Database User Setup

### MySQL / MariaDB

```sql
CREATE USER 'app_user' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS';
GRANT ALL ON mydb.* TO 'app_user'@'%';
```

### PostgreSQL

```sql
CREATE USER app_user WITH LOGIN;
GRANT rds_iam TO app_user;
```

## EKS Pod Identity Setup

1. Install the Pod Identity Agent addon
2. Create an IAM role with a trust policy for `pods.eks.amazonaws.com`
3. Attach an IAM policy allowing `rds-db:connect`
4. Create a pod identity association for your namespace/service account
5. Restart your pods

The AWS SDK default credential chain picks up Pod Identity credentials automatically. No code changes needed beyond enabling `use_iam_auth`.

*The option to force a specific credential provider exists via the `credential_provider` config option.*

## Token Caching

IAM auth tokens are valid for 15 minutes. The package caches them to avoid per-request STS calls:

1. **APCu** (highest priority) — shared memory, zero I/O. Best for PHP-FPM. Install `ext-apcu` and it's used automatically.
2. **Laravel cache store** — set `cache_store` to `file`, `redis`, `memcached`, etc. Good for queue workers or environments without APCu.
3. **No caching** — fresh token per connection. Fine for local dev (`use_iam_auth` is typically `false`) and short-lived CLI commands.

**Do not** set `cache_store` to `database` or `dynamodb` — this creates a circular dependency (need a DB connection to cache the token needed to open the DB connection). The package will throw a `RuntimeException` if you do.

**CLI and queue workers:** APCu is disabled in CLI by default (`apcu_enabled()` returns `false`). If you run queue workers with IAM auth, either set `apc.enable_cli=1` in your PHP CLI config, or configure a `cache_store` (e.g. `file` or `redis`).

**Cache security note:** When using `file`, `redis`, or `memcached` as the cache store, the IAM token is stored in plaintext. The token is short-lived (15 min) and scoped to a specific DB user, but ensure your cache backend is appropriately secured. APCu stores tokens in shared memory within the PHP process, which is not accessible externally.

**Bundled CA certificate:** The package includes the AWS RDS global CA bundle. This certificate bundle may become stale over time. If you encounter SSL verification errors, download the latest bundle from AWS and set `IAM_AUTH_SSL_CA_PATH` to point to it.

## AWS Credential Caching

When using IAM roles (IRSA, Pod Identity, instance profiles), the AWS SDK resolves credentials via network calls to STS or IMDS on every PHP-FPM request. Under high traffic this adds latency and can hit rate limits.

This package caches resolved AWS SDK credentials across requests, benefiting **all** AWS SDK calls made by your application (S3, SQS, SES, etc.), not just RDS token generation.

The same `cache_store` setting controls both RDS token caching and AWS credential caching (with separate cache keys and TTLs). APCu is always preferred when available.

**Cache security note:** Cached credentials are stored in plaintext in the configured backend. Ensure your cache backend is appropriately secured. APCu stores credentials in shared memory within the PHP process, which is not accessible externally.

## License

MIT
