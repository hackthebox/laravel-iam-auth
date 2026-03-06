<?php

namespace Hackthebox\RdsIamAuth\Connectors;

use Hackthebox\RdsIamAuth\RdsAuthTokenProvider;
use Illuminate\Database\Connectors\MariaDbConnector;
use PDO;

class RdsIamMariaDbConnector extends MariaDbConnector
{
    use InjectsIamToken;

    public function __construct(private readonly RdsAuthTokenProvider $tokenProvider)
    {
    }

    protected function getTokenProvider(): RdsAuthTokenProvider
    {
        return $this->tokenProvider;
    }

    protected function applyIamSslOptions(array $options): array
    {
        if (! isset($options[PDO::MYSQL_ATTR_SSL_CA])) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = config('rds-iam-auth.ssl_ca_path');
        }

        $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] ??= true;

        return $options;
    }

    protected function getDefaultPort(): int
    {
        return 3306;
    }
}
