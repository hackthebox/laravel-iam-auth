<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Database\Connectors\MariaDbConnector;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;

class IamMariaDbConnectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IamAuthServiceProvider::class];
    }

    public function test_extends_mariadb_connector(): void
    {
        $this->assertTrue(is_subclass_of(IamMariaDbConnector::class, MariaDbConnector::class));
    }

    public function test_injects_iam_token_when_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.eu-central-1.rds.amazonaws.com', 3306, 'app', 'eu-central-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(IamMariaDbConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn, $username, $password, $options) {
                return $password === 'iam-token-value'
                    && isset($options[PDO::MYSQL_ATTR_SSL_CA]);
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.eu-central-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'eu-central-1',
        ];

        $result = $connector->createConnection('mysql:host=my-rds', $config, []);

        $this->assertSame($pdo, $result);
    }

    public function test_skips_iam_when_not_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldNotReceive('getToken');

        $connector = Mockery::mock(IamMariaDbConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn, $username, $password) {
                return $password === 'static-password';
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'localhost',
            'port' => 3306,
            'username' => 'app',
            'password' => 'static-password',
            'use_iam_auth' => false,
        ];

        $connector->createConnection('mysql:host=localhost', $config, []);
    }
}
