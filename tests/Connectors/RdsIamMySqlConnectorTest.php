<?php

namespace Hackthebox\RdsIamAuth\Tests\Connectors;

use Hackthebox\RdsIamAuth\Connectors\RdsIamMySqlConnector;
use Hackthebox\RdsIamAuth\RdsAuthTokenProvider;
use Hackthebox\RdsIamAuth\RdsIamAuthServiceProvider;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;

class RdsIamMySqlConnectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [RdsIamAuthServiceProvider::class];
    }

    public function test_skips_iam_when_not_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldNotReceive('getToken');

        $connector = Mockery::mock(RdsIamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        // When use_iam_auth is false, parent::createConnection should be called with original password
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

        $result = $connector->createConnection('mysql:host=localhost', $config, []);

        $this->assertSame($pdo, $result);
    }

    public function test_injects_iam_token_when_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(RdsIamMySqlConnector::class, [$tokenProvider])
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
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ];

        $result = $connector->createConnection('mysql:host=my-rds.cluster.us-east-1.rds.amazonaws.com', $config, []);

        $this->assertSame($pdo, $result);
    }

    public function test_uses_default_port_when_not_specified(): void
    {
        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(RdsIamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);
        $connector->shouldReceive('createPdoConnection')->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ];

        $connector->createConnection('mysql:host=my-rds', $config, []);
    }

    public function test_does_not_override_existing_ssl_ca(): void
    {
        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(RdsIamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $customCaPath = '/custom/ca.pem';

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn, $username, $password, $options) use ($customCaPath) {
                return $options[PDO::MYSQL_ATTR_SSL_CA] === $customCaPath;
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ];

        $connector->createConnection('mysql:host=my-rds', $config, [
            PDO::MYSQL_ATTR_SSL_CA => $customCaPath,
        ]);
    }

    public function test_uses_config_region_as_fallback(): void
    {
        config(['rds-iam-auth.region' => 'eu-west-1']);

        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.eu-west-1.rds.amazonaws.com', 3306, 'app', 'eu-west-1')
            ->andReturn('token');

        $connector = Mockery::mock(RdsIamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);
        $connector->shouldReceive('createPdoConnection')->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.eu-west-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            // no 'region' key — should fall back to config
        ];

        $connector->createConnection('mysql:host=my-rds', $config, []);
    }
}
