<?php

return [

    /*
    |--------------------------------------------------------------------------
    | AWS Region
    |--------------------------------------------------------------------------
    |
    | The AWS region where your RDS instances are located. This is used as a
    | fallback when the 'region' key is not set on a specific database
    | connection. Per-connection 'region' takes precedence.
    |
    */

    'region' => env('AWS_DEFAULT_REGION', env('AWS_REGION', 'us-east-1')),

    /*
    |--------------------------------------------------------------------------
    | AWS Credential Provider
    |--------------------------------------------------------------------------
    |
    | The AWS credential provider used to sign IAM auth tokens. The default
    | uses the full SDK credential chain. Override to force a specific
    | provider when multiple credential sources exist (e.g. Pod Identity
    | over env vars).
    |
    | Supported: 'default', 'environment', 'ecs', 'web_identity',
    |            'instance_profile', 'sso', 'ini'
    |
    */

    'credential_provider' => env('RDS_IAM_CREDENTIAL_PROVIDER', 'default'),

    /*
    |--------------------------------------------------------------------------
    | Token Cache Store
    |--------------------------------------------------------------------------
    |
    | The Laravel cache store to use for caching IAM auth tokens when APCu
    | is not available. Set to null to disable Laravel cache fallback.
    |
    | APCu always takes priority when available (best for PHP-FPM).
    |
    | WARNING: Do not use 'database' or 'dynamodb' — this would create a
    | circular dependency (need DB to cache the token needed to open DB).
    | The package will throw an exception if you do.
    |
    | Recommended: 'file', 'redis', 'memcached', or null.
    |
    */

    'cache_store' => env('RDS_IAM_CACHE_STORE'),

    /*
    |--------------------------------------------------------------------------
    | Token Cache TTL
    |--------------------------------------------------------------------------
    |
    | How long (in seconds) to cache the IAM auth token. RDS IAM tokens are
    | valid for 15 minutes. The default of 600 seconds (10 min) leaves a
    | 5-minute buffer before expiry.
    |
    | Applies to both APCu and Laravel cache store.
    |
    */

    'cache_ttl' => (int) env('RDS_IAM_CACHE_TTL', 600),

    /*
    |--------------------------------------------------------------------------
    | PostgreSQL SSL Mode
    |--------------------------------------------------------------------------
    |
    | The sslmode to use for PostgreSQL connections with IAM auth. This
    | overrides any 'sslmode' set on the database connection config to
    | prevent accidental downgrade of SSL verification.
    |
    | Recommended: 'verify-full' (verifies server certificate and hostname).
    | Only change this if you understand the security implications.
    |
    */

    'pgsql_sslmode' => env('RDS_IAM_PGSQL_SSLMODE', 'verify-full'),

    /*
    |--------------------------------------------------------------------------
    | SSL CA Certificate Path
    |--------------------------------------------------------------------------
    |
    | Path to the AWS RDS combined CA bundle. Used for SSL verification on
    | all drivers when IAM auth is enabled (MySQL, MariaDB, PostgreSQL).
    |
    | Download from: https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
    |
    */

    'ssl_ca_path' => env('RDS_IAM_SSL_CA_PATH'),

];
