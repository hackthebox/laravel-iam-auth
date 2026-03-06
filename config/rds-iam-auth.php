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
    | Token Cache TTL
    |--------------------------------------------------------------------------
    |
    | How long (in seconds) to cache the IAM auth token in APCu. RDS IAM
    | tokens are valid for 15 minutes. The default of 600 seconds (10 min)
    | leaves a 5-minute buffer before expiry.
    |
    | Requires the APCu extension to be installed and enabled.
    |
    */

    'cache_ttl' => (int) env('RDS_IAM_CACHE_TTL', 600),

    /*
    |--------------------------------------------------------------------------
    | SSL CA Certificate Path
    |--------------------------------------------------------------------------
    |
    | Path to the AWS RDS combined CA bundle. Required for MySQL and MariaDB
    | connections using IAM auth (the token must be sent over SSL).
    |
    | For PostgreSQL, configure 'sslmode' and 'sslrootcert' directly on the
    | database connection in config/database.php.
    |
    | Download from: https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
    |
    */

    'ssl_ca_path' => env('RDS_IAM_SSL_CA_PATH', '/etc/ssl/certs/rds-combined-ca-bundle.pem'),

];
