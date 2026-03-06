<?php

namespace Hackthebox\RdsIamAuth\Connectors;

use Illuminate\Database\Connectors\PostgresConnector;

class RdsIamPostgresConnector extends PostgresConnector
{
    use InjectsIamToken;

    /**
     * Establish a database connection, ensuring SSL is configured when
     * IAM auth is enabled. PostgreSQL handles SSL via DSN parameters
     * (built by the parent's getDsn method), not PDO options.
     */
    public function connect(array $config)
    {
        if (! empty($config['use_iam_auth'])) {
            $config['sslmode'] ??= 'verify-full';
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
