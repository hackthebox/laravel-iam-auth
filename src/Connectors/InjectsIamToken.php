<?php

namespace Hackthebox\IamAuth\Connectors;

use Aws\Credentials\CredentialsInterface;
use Hackthebox\IamAuth\AwsCredentialCache;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use PDO;
use PDOException;

trait InjectsIamToken
{
    /**
     * Get the token provider instance.
     */
    abstract protected function getTokenProvider(): RdsTokenProvider;

    /**
     * Create a new PDO connection, injecting an IAM auth token as the
     * password when 'use_iam_auth' is enabled on the connection config.
     */
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
        $cacheKey = "rds_iam:{$config['host']}:$port:{$config['username']}:$region";

        $config['password'] = $this->getTokenProvider()->getToken(
            $config['host'],
            $port,
            $config['username'],
            $region,
        );

        $options = $this->applyIamSslOptions($options);

        try {
            return parent::createConnection($dsn, $config, $options);
        } catch (PDOException $e) {
            if ($this->isAuthRejection($e)) {
                $this->logAuthRejection($config, $cacheKey);
            }
            throw $e;
        }
    }

    private function isAuthRejection(PDOException $e): bool
    {
        $sqlstate = (string) ($e->errorInfo[0] ?? '');
        $driverCode = $e->errorInfo[1] ?? null;

        $isPostgresClass28 = str_starts_with($sqlstate, '28');
        $isMysqlAccessDenied = $driverCode === 1045;

        return $isPostgresClass28 || $isMysqlAccessDenied;
    }

    private function logAuthRejection(array $config, string $cacheKey): void
    {
        $creds = null;

        if (function_exists('apcu_fetch') && apcu_enabled()) {
            $cached = apcu_fetch(AwsCredentialCache::CACHE_KEY, $credFound);
            if ($credFound && $cached instanceof CredentialsInterface) {
                $creds = $cached;
            }
        }

        Log::warning('iam-auth.rds-auth-rejected', [
            'cache_key' => $cacheKey,
            'username' => $config['username'] ?? null,
            'host' => $config['host'] ?? null,
            'cred_present' => $creds !== null,
            'cred_is_expired' => $creds?->isExpired(),
            'cred_expires_in_s' => $creds && $creds->getExpiration()
                ? $creds->getExpiration() - time()
                : null,
            'cred_access_key_prefix' => $creds?->getAccessKeyId()
                ? substr($creds->getAccessKeyId(), 0, 8)
                : null,
        ]);
    }

    /**
     * Validate that required IAM config values are present.
     */
    private function validateIamConfig(array $config): void
    {
        if (empty($config['host']) || ! is_string($config['host'])) {
            throw new InvalidArgumentException(
                'IAM auth requires a non-empty "host" in the database connection config.'
            );
        }

        if (empty($config['username']) || ! is_string($config['username'])) {
            throw new InvalidArgumentException(
                'IAM auth requires a non-empty "username" in the database connection config.'
            );
        }

        $region = $config['region'] ?? config('iam-auth.region');
        if (empty($region) || ! is_string($region)) {
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

    /**
     * Apply driver-specific SSL options required for IAM auth.
     */
    abstract protected function applyIamSslOptions(array $options): array;

    /**
     * Get the default port for this driver.
     */
    abstract protected function getDefaultPort(): int;
}
