<?php

namespace Hackthebox\IamAuth\Connectors;

use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use PDO;
use PDOException;
use Throwable;

trait InjectsIamToken
{
    private const MYSQL_ACCESS_DENIED = 1045;

    private const PGSQL_CONNECT_FAILURE = '08006';

    private const PGSQL_FATAL_ERROR = 7;

    /**
     * RDS grants IAM access through the `rds_iam` role, which pg_hba maps to PAM, so a
     * genuine IAM rejection is the first of these. The second is deliberate breadth: a
     * role that is not IAM-enabled falls back to scram and produces it instead, and it
     * is also what a non-PAM front end such as RDS Proxy may surface. Re-signing fixes
     * a rotation race, not a missing grant, so the second wording costs one wasted
     * retry on a misconfigured role, bounded and documented in the README.
     */
    private const PGSQL_AUTH_REJECTION_MESSAGES = [
        'pam authentication failed',
        'password authentication failed',
    ];

    abstract protected function getTokenProvider(): RdsTokenProvider;

    public function createConnection($dsn, array $config, array $options): PDO
    {
        if (empty($config['use_iam_auth'])) {
            return parent::createConnection($dsn, $config, $options);
        }

        $this->validateIamConfig($config);

        $port = isset($config['port']) && $config['port'] !== ''
            ? (int) $config['port']
            : $this->getDefaultPort();

        $region = $config['region'] ?? config('iam-auth.region');
        $tokenProvider = $this->getTokenProvider();

        $config['password'] = $tokenProvider->getToken(
            $config['host'], $port, $config['username'], $region,
        );

        $options = $this->applyIamSslOptions($options);

        try {
            // parent::createConnection (not createPdoConnection): preserves Laravel's
            // tryAgainIfCausedByLostConnection wrapper around the PDO instantiation.
            return parent::createConnection($dsn, $config, $options);
        } catch (PDOException $e) {
            if (!$this->isAuthRejection($e)) {
                throw $e;
            }

            $this->logAuthRejection($config);

            $config['password'] = $tokenProvider->getToken(
                $config['host'], $port, $config['username'], $region,
                forceFresh: true,
            );

            try {
                return parent::createConnection($dsn, $config, $options);
            } catch (PDOException $retryE) {
                if ($this->isAuthRejection($retryE)) {
                    $this->logAuthRejectionRetryFailed($config);
                }
                throw $retryE;
            }
        }
    }

    protected function causedByLostConnection(Throwable $e): bool
    {
        if ($e instanceof PDOException && $this->isAuthRejection($e)) {
            return false;
        }
        return parent::causedByLostConnection($e);
    }

    private function isAuthRejection(PDOException $e): bool
    {
        $sqlstate = (string) ($e->errorInfo[0] ?? '');

        // Class 28 never reaches this method from pdo_pgsql or pdo_mysql during
        // connection establishment; it is kept as a forward-compatible guard, not as
        // the mechanism that protects PostgreSQL. See isPgsqlAuthRejection().
        return str_starts_with($sqlstate, '28')
            || ($e->errorInfo[1] ?? null) === self::MYSQL_ACCESS_DENIED
            || $this->isPgsqlAuthRejection($e);
    }

    /**
     * A failed PQconnectdb yields no PGresult, so libpq cannot supply a SQLSTATE and
     * pdo_pgsql substitutes 08006 with PGRES_FATAL_ERROR for every connect-time
     * failure, discarding the server's real SQLSTATE (28P01 for a rejected password).
     * The server message is therefore the only signal separating an auth rejection
     * from a network failure. Verified against PostgreSQL 14, 15, 16, 17 and 18.
     */
    private function isPgsqlAuthRejection(PDOException $e): bool
    {
        if ((string) ($e->errorInfo[0] ?? '') !== self::PGSQL_CONNECT_FAILURE) {
            return false;
        }

        if (($e->errorInfo[1] ?? null) !== self::PGSQL_FATAL_ERROR) {
            return false;
        }

        $driverMessage = strtolower((string) ($e->errorInfo[2] ?? $e->getMessage()));

        foreach (self::PGSQL_AUTH_REJECTION_MESSAGES as $needle) {
            if (str_contains($driverMessage, $needle)) {
                return true;
            }
        }

        return false;
    }

    private function logAuthRejection(array $config): void
    {
        Log::warning('iam-auth.rds-auth-rejected', $this->rejectionPayload($config));
    }

    private function logAuthRejectionRetryFailed(array $config): void
    {
        Log::warning('iam-auth.rds-auth-rejected-retry-failed', $this->rejectionPayload($config));
    }

    private function rejectionPayload(array $config): array
    {
        return [
            'username' => $config['username'] ?? null,
            'host' => $config['host'] ?? null,
            ...$this->getTokenProvider()->credentialSnapshot(),
        ];
    }

    private function validateIamConfig(array $config): void
    {
        if (empty($config['host']) || !is_string($config['host'])) {
            throw new InvalidArgumentException(
                'IAM auth requires a non-empty "host" in the database connection config.'
            );
        }

        if (empty($config['username']) || !is_string($config['username'])) {
            throw new InvalidArgumentException(
                'IAM auth requires a non-empty "username" in the database connection config.'
            );
        }

        $region = $config['region'] ?? config('iam-auth.region');
        if (empty($region) || !is_string($region)) {
            throw new InvalidArgumentException(
                'IAM auth requires a non-empty "region" in the database connection config or iam-auth.region config.'
            );
        }

        if (isset($config['port']) && $config['port'] !== '') {
            $port = (int) $config['port'];
            if ($port < 1 || $port > 65535) {
                throw new InvalidArgumentException(
                    "IAM auth requires a valid port (1-65535), got '{$config['port']}'."
                );
            }
        }
    }

    abstract protected function applyIamSslOptions(array $options): array;
    abstract protected function getDefaultPort(): int;
}
