# Laravel RDS IAM Auth

RDS IAM authentication for Laravel MySQL, MariaDB, and PostgreSQL connections. Designed for EKS workloads using Pod Identity or IRSA — no sidecars, no static credentials.

## How It Works

This package overrides Laravel's database connectors for MySQL, MariaDB, and PostgreSQL. When `use_iam_auth` is enabled on a connection, the connector generates a short-lived IAM auth token (via the AWS SDK) and uses it as the database password. Tokens are cached via APCu (preferred) or a configurable Laravel cache store to avoid per-request STS calls.

The package does **not** introduce a new database driver. Laravel's `MySqlConnection`, `MariaDbConnection`, and `PostgresConnection` are used as-is.

## Requirements

- PHP >= 8.2
- Laravel 11 or 12
- AWS SDK for PHP >= 3.249 (Pod Identity support)
- APCu extension (recommended for production — caches tokens across FPM requests)
- RDS instance with IAM authentication enabled
- SSL CA bundle (bundled — override via `RDS_IAM_SSL_CA_PATH` env if needed)

## Installation

```bash
composer require hackthebox/laravel-rds-iam-auth
```

The service provider is auto-discovered. To publish the config:

```bash
php artisan vendor:publish --tag=rds-iam-auth-config
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
    'region' => env('AWS_REGION', 'eu-central-1'),
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
    'region' => env('AWS_REGION', 'eu-central-1'),
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
AWS_REGION=eu-central-1
```

**Local development:**

```env
DB_USE_IAM_AUTH=false
DB_PASSWORD=secret
```

### Package Config

The package config (`config/rds-iam-auth.php`):

| Key | Default | Description |
|---|---|---|
| `region` | `AWS_DEFAULT_REGION` / `AWS_REGION` env | Fallback region when not set on connection |
| `cache_store` | `null` | Laravel cache store for token caching when APCu is unavailable. Use `file`, `redis`, `memcached`, etc. **Never** `database` or `dynamodb`. |
| `cache_ttl` | `600` (10 min) | Cache TTL in seconds (APCu and Laravel cache). Tokens are valid for 15 min. |
| `pgsql_sslmode` | `verify-full` | SSL mode for PostgreSQL IAM connections. Overrides connection-level `sslmode` to prevent accidental downgrade. Override with `RDS_IAM_PGSQL_SSLMODE` env. |
| `ssl_ca_path` | Bundled `global-bundle.pem` | Path to the RDS CA bundle. Override with `RDS_IAM_SSL_CA_PATH` env. |

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

## Token Caching

IAM auth tokens are valid for 15 minutes. The package caches them to avoid per-request STS calls:

1. **APCu** (highest priority) — shared memory, zero I/O. Best for PHP-FPM. Install `ext-apcu` and it's used automatically.
2. **Laravel cache store** — set `cache_store` to `file`, `redis`, `memcached`, etc. Good for queue workers or environments without APCu.
3. **No caching** — fresh token per connection. Fine for local dev (`use_iam_auth` is typically `false`) and short-lived CLI commands.

**Do not** set `cache_store` to `database` or `dynamodb` — this creates a circular dependency (need a DB connection to cache the token needed to open the DB connection). The package will throw a `RuntimeException` if you do.

**CLI and queue workers:** APCu is disabled in CLI by default (`apcu_enabled()` returns `false`). If you run queue workers with IAM auth, either set `apc.enable_cli=1` in your PHP CLI config, or configure a `cache_store` (e.g. `file` or `redis`).

**Cache security note:** When using `file`, `redis`, or `memcached` as the cache store, the IAM token is stored in plaintext. The token is short-lived (15 min) and scoped to a specific DB user, but ensure your cache backend is appropriately secured. APCu stores tokens in shared memory within the PHP process, which is not accessible externally.

**Bundled CA certificate:** The package includes the AWS RDS global CA bundle. This certificate bundle may become stale over time. If you encounter SSL verification errors, download the latest bundle from AWS and set `RDS_IAM_SSL_CA_PATH` to point to it.

## License

MIT
