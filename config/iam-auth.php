<?php

return [

    /*
    |--------------------------------------------------------------------------
    | AWS Region
    |--------------------------------------------------------------------------
    |
    | The AWS region used as a fallback when the 'region' key is not set on a
    | specific database connection. Per-connection 'region' takes precedence.
    |
    */

    'region' => env('AWS_DEFAULT_REGION', env('AWS_REGION', 'us-east-1')),

    /*
    |--------------------------------------------------------------------------
    | AWS Credential Provider
    |--------------------------------------------------------------------------
    |
    | The AWS credential provider used for all SDK operations (S3, SQS, SES,
    | RDS token generation, etc.). The default uses the full SDK credential
    | chain. Override to force a specific provider when multiple credential
    | sources exist (e.g. Pod Identity over env vars).
    |
    | Supported: 'default', 'environment', 'ecs', 'web_identity',
    |            'instance_profile', 'sso', 'ini'
    |
    */

    'credential_provider' => env('IAM_AUTH_CREDENTIAL_PROVIDER', 'default'),

    /*
    |--------------------------------------------------------------------------
    | Cache Store
    |--------------------------------------------------------------------------
    |
    | The Laravel cache store for caching RDS IAM auth tokens and resolved
    | AWS SDK credentials when APCu is not available. A single store is used
    | for both (with separate cache keys and TTLs).
    |
    | APCu always takes priority when available (best for PHP-FPM).
    | Set to null to disable Laravel cache fallback.
    |
    | WARNING: Do not use 'database' or 'dynamodb' -- circular dependency.
    |
    */

    'cache_store' => env('IAM_AUTH_CACHE_STORE'),

    /*
    |--------------------------------------------------------------------------
    | RDS Token Cache TTL
    |--------------------------------------------------------------------------
    |
    | How long (in seconds) to cache the RDS IAM auth token. Tokens are
    | valid for 15 minutes. The default of 600 seconds (10 min) leaves a
    | 5-minute buffer before expiry.
    |
    */

    'cache_ttl' => (int) env('IAM_AUTH_CACHE_TTL', 600),

    /*
    |--------------------------------------------------------------------------
    | PostgreSQL SSL Mode
    |--------------------------------------------------------------------------
    |
    | The sslmode for PostgreSQL connections with IAM auth. Overrides any
    | 'sslmode' on the database connection to prevent accidental downgrade.
    |
    */

    'pgsql_sslmode' => env('IAM_AUTH_PGSQL_SSLMODE', 'verify-full'),

    /*
    |--------------------------------------------------------------------------
    | SSL CA Certificate Path
    |--------------------------------------------------------------------------
    |
    | Path to the AWS RDS combined CA bundle for SSL verification on all
    | drivers when IAM auth is enabled (MySQL, MariaDB, PostgreSQL).
    |
    | Download: https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
    |
    */

    'ssl_ca_path' => env('IAM_AUTH_SSL_CA_PATH'),

];
