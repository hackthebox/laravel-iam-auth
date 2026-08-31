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
        $driverCode = $e->errorInfo[1] ?? null;
        $driverMessage = strtolower((string) ($e->errorInfo[2] ?? $e->getMessage()));

        return str_starts_with($sqlstate, '28')
            || $driverCode === 1045
            || (
                $sqlstate === '08006'
                && (int) $driverCode === 7
                && str_contains($driverMessage, 'pam authentication failed')
            );
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
