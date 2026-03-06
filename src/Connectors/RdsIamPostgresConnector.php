<?php

namespace Hackthebox\RdsIamAuth\Connectors;

use Hackthebox\RdsIamAuth\RdsAuthTokenProvider;
use Illuminate\Database\Connectors\PostgresConnector;

class RdsIamPostgresConnector extends PostgresConnector
{
    use InjectsIamToken;

    public function __construct(private readonly RdsAuthTokenProvider $tokenProvider)
    {
    }

    protected function getTokenProvider(): RdsAuthTokenProvider
    {
        return $this->tokenProvider;
    }

    /**
     * Establish a database connection, ensuring SSL is configured when
     * IAM auth is enabled. PostgreSQL handles SSL via DSN parameters
     * (built by the parent's getDsn method), not PDO options.
     */
    public function connect(array $config): \PDO
    {
        if (! empty($config['use_iam_auth'])) {
            $config['sslmode'] = config('rds-iam-auth.pgsql_sslmode', 'verify-full');
            $config['sslrootcert'] ??= config('rds-iam-auth.ssl_ca_path');
        }

        return parent::connect($config);
    }

    protected function applyIamSslOptions(array $options): array
    {
        // PostgreSQL SSL is handled via DSN params in connect(), not PDO options.
        return $options;
    }

    protected function getDefaultPort(): int
    {
        return 5432;
    }
}
