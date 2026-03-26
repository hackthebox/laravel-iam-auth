<?php

namespace Hackthebox\IamAuth\Connectors;

use Hackthebox\IamAuth\RdsTokenProvider;
use InvalidArgumentException;
use PDO;

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

        $config['password'] = $this->getTokenProvider()->getToken(
            $config['host'],
            $port,
            $config['username'],
            $config['region'] ?? config('iam-auth.region'),
        );

        $options = $this->applyIamSslOptions($options);

        return parent::createConnection($dsn, $config, $options);
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
