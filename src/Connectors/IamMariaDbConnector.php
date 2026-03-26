<?php

namespace Hackthebox\IamAuth\Connectors;

use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Database\Connectors\MariaDbConnector;
use PDO;

class IamMariaDbConnector extends MariaDbConnector
{
    use InjectsIamToken;

    public function __construct(private readonly RdsTokenProvider $tokenProvider)
    {
    }

    protected function getTokenProvider(): RdsTokenProvider
    {
        return $this->tokenProvider;
    }

    protected function applyIamSslOptions(array $options): array
    {
        if (! isset($options[PDO::MYSQL_ATTR_SSL_CA])) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = config('iam-auth.ssl_ca_path');
        }

        $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] ??= true;

        return $options;
    }

    protected function getDefaultPort(): int
    {
        return 3306;
    }
}
