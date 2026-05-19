# Laravel IAM Auth

AWS IAM authentication for Laravel: RDS database connections and SDK credential caching. Designed for EKS workloads using Pod Identity or IRSA (no sidecars, no static credentials).

## Features

- **RDS IAM Auth** — overrides Laravel's MySQL, MariaDB, and PostgreSQL connectors to generate short-lived IAM auth tokens via the AWS SDK when `use_iam_auth` is enabled on a connection.
- **AWS Credential Caching** — caches resolved AWS SDK credentials across PHP-FPM requests (APCu-first), benefiting all AWS SDK calls (S3, SQS, SES, etc.).

## How It Works

This package overrides Laravel's database connectors for MySQL, MariaDB, and PostgreSQL. When `use_iam_auth` is enabled on a connection, the connector generates a short-lived IAM auth token (via the AWS SDK) and uses it as the database password. The token is generated fresh on each connection; the AWS SDK credential resolution that backs the token signature is cached across PHP-FPM requests (APCu-first).

The package does **not** introduce a new database driver. Laravel's `MySqlConnection`, `MariaDbConnection`, and `PostgresConnection` are used as-is.

The package also extends the aws/aws-sdk-php-laravel SDK singleton to cache resolved AWS credentials across PHP-FPM requests, benefiting all AWS SDK calls in your application.

## Driver Support

Supports MySQL, MariaDB, and PostgreSQL. All three drivers share the same connector trait (`InjectsIamToken`), so the auth-token signing, cache-defense, and auth-rejection-detection behavior is identical across them.

## Requirements

- PHP >= 8.2
- Laravel 11 or 12
- aws/aws-sdk-php-laravel >= 3.7 and aws/aws-sdk-php >= 3.249 (both installed automatically)
- APCu extension (recommended for production — caches resolved AWS credentials across FPM requests)
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
| `credential_provider` | `default` | AWS credential provider for all SDK operations (S3, SQS, RDS, etc.). Override with `IAM_AUTH_CREDENTIAL_PROVIDER` env. Supported: `default`, `environment`, `ecs`, `web_identity`, `instance_profile`, `sso`, `ini`. |
| `cache_store` | `null` | Laravel cache store for caching resolved AWS credentials when APCu is unavailable. Use `file`, `redis`, `memcached`, etc. **Never** `database` or `dynamodb`. Override with `IAM_AUTH_CACHE_STORE` env. |
| `debug` | `false` | When `true`, emits verbose debug logging of credential and token cache state on every `getToken` call. High log volume; intended for short investigation soaks only. Override with `IAM_AUTH_DEBUG` env. |
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

## Token Generation

IAM auth tokens are valid for 15 minutes and are generated fresh on each database connection. Because RDS token signing is local HMAC work using already-cached credentials, the cost per connection is negligible.

**Bundled CA certificate:** The package includes the AWS RDS global CA bundle. This certificate bundle may become stale over time. If you encounter SSL verification errors, download the latest bundle from AWS and set `IAM_AUTH_SSL_CA_PATH` to point to it.

## Defensive Behavior

**Expired-on-arrival credentials throw.** When the AWS SDK credential provider hands back a `Credentials` object that is already past its expiration, `AwsCredentialCacheStore::set()` throws a `RuntimeException` instead of caching them for use by the SigV4 signer, and emits a `Log::warning` under the channel `iam-auth.credentials-expired-on-arrival` for operator visibility.

**Auth rejection triggers a single retry with fresh credentials.** Any auth rejection from RDS that reaches the connector (SQLSTATE class `28` for PostgreSQL, native code `1045` for MySQL/MariaDB) triggers the following recovery sequence:

1. Log `iam-auth.rds-auth-rejected` (warning) with the current credential cache snapshot.
2. Evict the cached credentials (`AwsCredentialCacheStore::remove`).
3. Re-sign the RDS token against freshly resolved credentials (bypassing both memoize and the credential cache via a parallel `iam-auth.credential-provider-fresh` binding).
4. Retry the connection once.

If the retry also fails with an auth rejection, `iam-auth.rds-auth-rejected-retry-failed` is logged and the exception is re-thrown. This covers the common case of a credential rotation window landing between the credential cache write and the DB connect.

The credential snapshot in the warning reflects the cache state at the moment the warning fires. On a busy multi-worker pod a concurrent refresh between signing and rejection can produce a snapshot of post-rotation credentials; this is cosmetic and does not affect the retry logic.

**Performance note.** If you disable credential caching (no APCu, no `cache_store`), every DB connection will re-invoke the SDK credential chain. Keep credential caching enabled for IAM-auth workloads.

## Debugging

Set `IAM_AUTH_DEBUG=true` in your environment to enable verbose per-`getToken` logging. The package emits an `iam-auth.token-access` debug line on every call:

- `host`, `port`, `username`, `region`: connection target.
- `force_fresh`: whether the call bypassed the credential cache (i.e., this is a retry after auth rejection).
- `access_key_prefix`: first 8 characters of the AccessKeyId used to sign the token (never the full credential).

The `iam-auth.rds-auth-rejected` and `iam-auth.rds-auth-rejected-retry-failed` warnings are unconditional and fire regardless of `IAM_AUTH_DEBUG`.

This log volume is too high for steady-state production. Enable for short investigation soaks only. No credential secrets are ever logged.

## AWS Credential Caching

When using IAM roles (IRSA, Pod Identity, instance profiles), the AWS SDK resolves credentials via network calls to STS or IMDS on every PHP-FPM request. Under high traffic this adds latency and can hit rate limits.

This package caches resolved AWS SDK credentials across requests, benefiting **all** AWS SDK calls made by your application (S3, SQS, SES, etc.), not just RDS token generation.

The `cache_store` setting controls AWS credential caching. APCu is always preferred when available.

**Important:** Credential caching only applies to AWS clients created through the SDK singleton (e.g. `app('aws')->createS3()`). Clients instantiated directly (`new S3Client([...])`) bypass the singleton and do not benefit from cached credentials. Always resolve clients via the container:

```php
// Correct: uses cached credentials
$s3 = app('aws')->createS3();

// Bypasses credential caching
$s3 = new \Aws\S3\S3Client([...]);
```

**Cache security note:** Cached AWS credentials are stored in plaintext in the configured backend. Ensure your cache backend is appropriately secured. APCu stores credentials in shared memory within the PHP process, which is not accessible externally.

**Static credentials are not cached.** Credentials without a reported expiration (e.g. static env keys, `~/.aws/credentials` profiles without an `expiration`) cannot be safely cached because the package has no signal for when to evict them. Each request will re-invoke the SDK credential chain. This is intentional: the expired-on-arrival guard in `AwsCredentialCacheStore::set()` prevents storing credentials the SDK has already marked expired, but long-lived credentials have no expiration to check. Production workloads on IRSA / Pod Identity / instance profiles get full caching benefits because the SDK reports an expiration.

## Known upstream limitations

This package consciously does not work around the following AWS-side gaps. Each limitation is documented so consumers understand the behavior and where to file issues upstream if material.

### AWS SDK PHP issue #1714

`CredentialProvider::memoize(CredentialProvider::cache(...))` does not honor memoize's `REFRESH_WINDOW` buffer, because `cache()` short-circuits on `!isExpired()` without buffer. In practice, credentials may be returned to the SigV4 signer up to the millisecond of their stated expiration. The connector layer's single-retry on auth rejection (SQLSTATE 28 / native 1045) absorbs the small number of last-millisecond races this causes during credential rotation. We do not implement a client-side buffer.

### `CredentialProvider::memoize` has no invalidation hook

Once memoize has cached credentials in its closure-captured `static $result`, there is no API to invalidate it externally. The retry path therefore uses a parallel uncached credential provider binding (`iam-auth.credential-provider-fresh`) that bypasses both memoize and the credentials cache. Within a single failing request, subsequent DB connects after the retry will still see memoize's stale state. This is bounded by request duration.

### EKS Pod Identity Agent may serve credentials AWS has invalidated

The agent's internal cache can lag behind server-side session revocation. No client-side mechanism can detect this. The connector retry helps only if the agent has rotated between attempts. If your observability shows sustained `iam-auth.rds-auth-rejected-retry-failed` events, file with `aws/containers-roadmap`; do not add client-side mitigation here.

### AWS SDK retry middleware does not see RDS IAM auth errors

RDS speaks the database wire protocol, so auth rejections arrive as `PDOException`, never as AWS SDK exceptions. The SDK's credential-refresh retry cannot apply. The connector-layer retry in `InjectsIamToken` is the correct place for the equivalent recovery logic.

## Migrating from v1

v2 is a breaking change with the following migration steps:

1. Update `composer.json` to require `^2.0`.
2. Remove `cache_ttl` and `credentials_expiry_buffer` from any `config/iam-auth.php` overrides. The RDS token cache is gone (tokens are signed per call); credential cache expiry is governed by the AWS SDK's standard `Aws\CacheInterface` contract.
3. Remove the `IAM_AUTH_CACHE_TTL` and `IAM_AUTH_CREDENTIALS_EXPIRY_BUFFER` env vars from deployment manifests.
4. Existing APCu/Laravel cache entries from v1 will be discarded automatically (different cache key, different value shape). No migration step required.
5. Custom handlers or middleware on the `aws` SDK singleton now actually survive (v2 stops rebuilding the singleton).

After deployment, expect occasional `iam-auth.rds-auth-rejected` warnings (followed by silent successful retries) during credential rotation windows. Sustained `iam-auth.rds-auth-rejected-retry-failed` events indicate the residual case and should be escalated upstream.

## License

MIT
