<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use InvalidArgumentException;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;

class IamMySqlConnectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IamAuthServiceProvider::class];
    }

    public function test_skips_iam_when_not_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldNotReceive('getToken');

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
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
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
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
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
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
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
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
        config(['iam-auth.region' => 'eu-west-1']);

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.eu-west-1.rds.amazonaws.com', 3306, 'app', 'eu-west-1')
            ->andReturn('token');

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
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

    public function test_throws_on_missing_host(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty "host"');

        $connector->createConnection('mysql:host=', [
            'host' => '',
            'port' => 3306,
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ], []);
    }

    public function test_throws_on_missing_username(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty "username"');

        $connector->createConnection('mysql:host=rds', [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => '',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ], []);
    }

    public function test_throws_on_missing_region(): void
    {
        config(['iam-auth.region' => null]);

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('non-empty "region"');

        $connector->createConnection('mysql:host=rds', [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
        ], []);
    }

    public function test_enables_ssl_server_cert_verification(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn, $username, $password, $options) {
                return $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] === true;
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

        $connector->createConnection('mysql:host=my-rds', $config, []);
    }

    public function test_throws_on_invalid_port(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('valid port (1-65535)');

        $connector->createConnection('mysql:host=rds', [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 0,
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ], []);
    }

    public function test_uses_default_port_when_port_is_empty_string(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(IamMySqlConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);
        $connector->shouldReceive('createPdoConnection')->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => '',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ];

        $connector->createConnection('mysql:host=my-rds', $config, []);
    }
}
