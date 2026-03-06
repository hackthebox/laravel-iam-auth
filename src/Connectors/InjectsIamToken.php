<?php

namespace Hackthebox\RdsIamAuth\Connectors;

use Hackthebox\RdsIamAuth\RdsAuthTokenProvider;

trait InjectsIamToken
{
    public function __construct(private readonly RdsAuthTokenProvider $tokenProvider)
    {
    }

    /**
     * Create a new PDO connection, injecting an IAM auth token as the
     * password when 'use_iam_auth' is enabled on the connection config.
     */
    public function createConnection($dsn, array $config, array $options)
    {
        if (empty($config['use_iam_auth'])) {
            return parent::createConnection($dsn, $config, $options);
        }

        $config['password'] = $this->tokenProvider->getToken(
            $config['host'],
            (int) ($config['port'] ?? $this->getDefaultPort()),
            $config['username'],
            $config['region'] ?? config('rds-iam-auth.region'),
        );

        $options = $this->applyIamSslOptions($options);

        return parent::createConnection($dsn, $config, $options);
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
