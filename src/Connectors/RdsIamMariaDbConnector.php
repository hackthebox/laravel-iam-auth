<?php

namespace Hackthebox\RdsIamAuth\Connectors;

use Illuminate\Database\Connectors\MariaDbConnector;
use PDO;

class RdsIamMariaDbConnector extends MariaDbConnector
{
    use InjectsIamToken;

    protected function applyIamSslOptions(array $options): array
    {
        if (! isset($options[PDO::MYSQL_ATTR_SSL_CA])) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = config('rds-iam-auth.ssl_ca_path');
        }

        return $options;
    }

    protected function getDefaultPort(): int
    {
        return 3306;
    }
}
