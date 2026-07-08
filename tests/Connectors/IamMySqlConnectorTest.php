<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;
use PDOException;
use RuntimeException;
use SensitiveParameter;

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

    public function test_retry_succeeds_after_auth_rejection_1045(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->exactly(2))
            ->method('getToken')
            ->willReturnCallback(function ($h, $p, $u, $r, $force = false) {
                static $i = 0;
                $i++;
                $this->assertSame($i === 2, $force, 'second call must forceFresh, first must not');
                return $i === 1 ? 'token1' : 'token2';
            });

        $connector = $this->makeConnector(
            $tokenProvider,
            attempts: [$this->mysqlAuthRejection(), $this->createMock(PDO::class)],
        );

        $pdo = $connector->createConnection('mysql:host=h;dbname=d', $this->iamConfig(), []);
        $this->assertNotNull($pdo);

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldNotHaveReceived('warning', ['iam-auth.rds-auth-rejected-retry-failed', Mockery::any()]);
    }

    private function mysqlAuthRejection(string $msg = 'access denied'): PDOException
    {
        $e = new PDOException($msg);
        $e->errorInfo = ['HY000', 1045, $msg];
        return $e;
    }

    private function iamConfig(): array
    {
        return [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => 'iam_user',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ];
    }

    private function makeConnector(
        RdsTokenProvider $tokenProvider,
        array $attempts,
    ): IamMySqlConnector {
        return new class($tokenProvider, $attempts) extends IamMySqlConnector {
            public int $callIdx = 0;
            public array $attempts;

            public function __construct(
                RdsTokenProvider $tp,
                array $attempts,
            ) {
                parent::__construct($tp);
                $this->attempts = $attempts;
            }

            protected function createPdoConnection($dsn, $username, #[SensitiveParameter] $password, $options): PDO
            {
                $entry = $this->attempts[$this->callIdx++] ?? null;
                if ($entry instanceof PDOException) {
                    throw $entry;
                }
                if ($entry instanceof PDO) {
                    return $entry;
                }
                throw new RuntimeException('no attempt seeded at index '.($this->callIdx - 1));
            }
        };
    }
}
