# Laravel RDS IAM Auth

RDS IAM authentication for Laravel MySQL, MariaDB, and PostgreSQL connections. Designed for EKS workloads using Pod Identity or IRSA — no sidecars, no static credentials.

## How It Works

This package overrides Laravel's database connectors for MySQL, MariaDB, and PostgreSQL. When `use_iam_auth` is enabled on a connection, the connector generates a short-lived IAM auth token (via the AWS SDK) and uses it as the database password. Tokens are cached in APCu to avoid per-request STS calls.

The package does **not** introduce a new database driver. Laravel's `MySqlConnection`, `MariaDbConnection`, and `PostgresConnection` are used as-is.

## Requirements

- PHP >= 8.2
- Laravel 11 or 12
- AWS SDK for PHP >= 3.249 (Pod Identity support)
- APCu extension (recommended for production — caches tokens across FPM requests)
- RDS instance with IAM authentication enabled
- SSL CA bundle ([download](https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem))

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
    'sslmode' => 'prefer',
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

The package config (`config/rds-iam-auth.php`) has three options:

| Key | Default | Description |
|---|---|---|
| `region` | `AWS_DEFAULT_REGION` / `AWS_REGION` env | Fallback region when not set on connection |
| `cache_ttl` | `600` (10 min) | APCu cache TTL in seconds. Tokens are valid for 15 min. |
| `ssl_ca_path` | `/etc/ssl/certs/rds-combined-ca-bundle.pem` | Path to the RDS CA bundle |

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

## APCu

In production (PHP-FPM), APCu caches the IAM token in shared memory. Only one request every ~10 minutes generates a new token — all others get a shared-memory lookup.

Without APCu (CLI, local dev), a fresh token is generated per connection. This is fine since `use_iam_auth` is typically `false` locally, and CLI commands (migrations, etc.) are short-lived.

## License

MIT
