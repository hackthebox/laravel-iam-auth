<?php

namespace Hackthebox\IamAuth\Connectors;

use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Database\Connectors\PostgresConnector;
use InvalidArgumentException;
use PDO;

class IamPostgresConnector extends PostgresConnector
{
    use InjectsIamToken;

    private const SECURE_SSL_MODES = ['verify-ca', 'verify-full'];

    public function __construct(
        private readonly RdsTokenProvider $tokenProvider,
    ) {
    }

    protected function getTokenProvider(): RdsTokenProvider
    {
        return $this->tokenProvider;
    }

    public function connect(array $config): PDO
    {
        if (!empty($config['use_iam_auth'])) {
            $sslmode = config('iam-auth.pgsql_sslmode', 'verify-full');

            if (!in_array($sslmode, self::SECURE_SSL_MODES, true)) {
                throw new InvalidArgumentException(
                    "IAM auth requires PostgreSQL sslmode to be 'verify-ca' or 'verify-full', got '$sslmode'. "
                    ."Check the 'pgsql_sslmode' value in config/iam-auth.php or the IAM_AUTH_PGSQL_SSLMODE env var."
                );
            }

            $config['sslmode'] = $sslmode;
            $config['sslrootcert'] ??= config('iam-auth.ssl_ca_path');
        }

        return parent::connect($config);
    }

    protected function applyIamSslOptions(array $options): array
    {
        return $options;
    }

    protected function getDefaultPort(): int
    {
        return 5432;
    }
}
