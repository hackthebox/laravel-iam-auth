<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Database\Connectors\PostgresConnector;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;
use PDOException;

class IamPostgresConnectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IamAuthServiceProvider::class];
    }

    public function test_extends_postgres_connector(): void
    {
        $this->assertTrue(is_subclass_of(IamPostgresConnector::class, PostgresConnector::class));
    }

    public function test_injects_iam_token_when_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 5432, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn, $username, $password) {
                return $password === 'iam-token-value';
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
        ];

        $result = $connector->createConnection('pgsql:host=my-rds', $config, []);

        $this->assertSame($pdo, $result);
    }

    public function test_sets_sslmode_when_iam_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn) {
                return str_contains($dsn, 'sslmode=verify-full');
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
        ];

        $connector->connect($config);
    }

    public function test_forces_sslmode_from_package_config(): void
    {
        config(['iam-auth.pgsql_sslmode' => 'verify-full']);

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn) {
                return str_contains($dsn, 'sslmode=verify-full');
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
            'sslmode' => 'prefer',
        ];

        $connector->connect($config);
    }

    public function test_sslrootcert_appears_in_dsn(): void
    {
        config(['iam-auth.ssl_ca_path' => '/path/to/ca-bundle.pem']);

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn) {
                return str_contains($dsn, 'sslrootcert=/path/to/ca-bundle.pem');
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
        ];

        $connector->connect($config);
    }

    public function test_connect_injects_token_and_ssl_dsn(): void
    {
        config(['iam-auth.ssl_ca_path' => '/path/to/ca-bundle.pem']);

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 5432, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn, $username, $password) {
                return $password === 'iam-token-value'
                    && str_contains($dsn, 'sslmode=verify-full')
                    && str_contains($dsn, 'sslrootcert=/path/to/ca-bundle.pem');
            })
            ->andReturn($pdo);

        $config = [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
        ];

        $result = $connector->connect($config);

        $this->assertSame($pdo, $result);
    }

    public function test_throws_on_insecure_sslmode(): void
    {
        config(['iam-auth.pgsql_sslmode' => 'prefer']);

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("sslmode to be 'verify-ca' or 'verify-full', got 'prefer'");

        $connector->connect([
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
        ]);
    }

    public function test_allows_verify_ca_sslmode(): void
    {
        config(['iam-auth.pgsql_sslmode' => 'verify-ca']);

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $pdo = Mockery::mock(PDO::class);

        $connector->shouldReceive('createPdoConnection')
            ->once()
            ->withArgs(function ($dsn) {
                return str_contains($dsn, 'sslmode=verify-ca');
            })
            ->andReturn($pdo);

        $connector->connect([
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
        ]);
    }

    public function test_skips_iam_when_not_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldNotReceive('getToken');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
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
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'app',
            'password' => 'static-password',
            'use_iam_auth' => false,
            'charset' => 'utf8',
        ];

        $connector->connect($config);
    }

    public function test_postgres_28p01_auth_rejection_logs_structured_warning(): void
    {
        $connector = $this->mockConnectorThatThrows($this->makePdoException(
            '28P01',
            'SQLSTATE[28P01]: Invalid authorization specification: 7 FATAL: password authentication failed for user "iam_user"',
        ));

        Log::spy();

        $connector->createConnection('pgsql:host=...', $this->iamConfig(), []);

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(fn (string $msg) => $msg === 'iam-auth.rds-auth-rejected');
    }

    public function test_postgres_28000_auth_rejection_logs_structured_warning(): void
    {
        $connector = $this->mockConnectorThatThrows($this->makePdoException(
            '28000',
            'SQLSTATE[28000]: Invalid authorization specification: 7 FATAL: no pg_hba.conf entry for host "10.0.4.26", user "iam_user"',
        ));

        Log::spy();

        $connector->createConnection('pgsql:host=...', $this->iamConfig(), []);

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(fn (string $msg) => $msg === 'iam-auth.rds-auth-rejected');
    }

    public function test_postgres_non_auth_pdo_exception_does_not_log_warning(): void
    {
        $connector = $this->mockConnectorThatThrows(
            $this->makePdoException('42501', "SQLSTATE[42501]: Insufficient privilege: 7 ERROR: permission denied for table users")
        );

        Log::spy();

        try {
            $connector->createConnection('pgsql:host=...', $this->iamConfig(), []);
        } catch (PDOException) {
        }

        Log::shouldNotHaveReceived('warning');
    }

    public function test_retry_succeeds_after_auth_rejection_28p01(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->exactly(2))
            ->method('getToken')
            ->willReturnCallback(function ($h, $p, $u, $r, $force = false) {
                static $i = 0;
                $i++;
                $this->assertSame($i === 2, $force);
                return $i === 1 ? 'token1' : 'token2';
            });

        $connector = $this->makeConnector(
            $tokenProvider,
            attempts: [$this->pgAuthRejection('28P01'), $this->createMock(PDO::class)],
        );

        $pdo = $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
        $this->assertNotNull($pdo);

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldNotHaveReceived('warning', ['iam-auth.rds-auth-rejected-retry-failed', Mockery::any()]);
    }

    public function test_retry_failure_logs_retry_failed_and_propagates_second_exception(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->method('getToken')->willReturn('token');

        $first = $this->pgAuthRejection('28000', 'first');
        $second = $this->pgAuthRejection('28P01', 'second');

        $connector = $this->makeConnector($tokenProvider, attempts: [$first, $second]);

        try {
            $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException $e) {
            $this->assertStringContainsString('second', $e->getMessage());
        }

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected-retry-failed', Mockery::any())->once();
    }

    public function test_non_auth_pdo_exception_propagates_without_retry(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->once())->method('getToken')->willReturn('token');

        $networkErr = new PDOException('connection timeout');
        $networkErr->errorInfo = ['08006', 7, 'connection failure'];

        $connector = $this->makeConnector($tokenProvider, attempts: [$networkErr]);

        $this->expectException(PDOException::class);
        $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);

        Log::shouldNotHaveReceived('warning');
    }

    public function test_non_auth_42501_does_not_trigger_retry(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->once())->method('getToken')->willReturn('token');

        $err = new PDOException('permission denied');
        $err->errorInfo = ['42501', 7, 'permission denied for table users'];

        $connector = $this->makeConnector($tokenProvider, attempts: [$err]);

        try {
            $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException) {
        }

        Log::shouldNotHaveReceived('warning');
    }

    public function test_credentials_exception_during_retry_propagates(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->method('getToken')->willReturnCallback(function ($h, $p, $u, $r, $force = false) {
            if ($force) {
                throw new \Aws\Exception\CredentialsException('agent unreachable');
            }
            return 'token';
        });

        $connector = $this->makeConnector(
            $tokenProvider,
            attempts: [$this->pgAuthRejection('28P01')],
        );

        try {
            $connector->createConnection('pgsql:host=h;dbname=d', $this->iamConfig(), []);
            $this->fail('expected CredentialsException');
        } catch (\Aws\Exception\CredentialsException) {
        }

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldNotHaveReceived('warning', ['iam-auth.rds-auth-rejected-retry-failed', Mockery::any()]);
    }

    private function pgAuthRejection(string $sqlstate = '28000', string $msg = 'invalid password'): PDOException
    {
        $e = new PDOException("SQLSTATE[$sqlstate]: $msg");
        $e->errorInfo = [$sqlstate, 7, $msg];
        return $e;
    }

    private function makeConnector(
        RdsTokenProvider $tokenProvider,
        array $attempts,
    ): IamPostgresConnector {
        return new class($tokenProvider, $attempts) extends IamPostgresConnector {
            public int $callIdx = 0;
            public array $attempts;

            public function __construct(
                RdsTokenProvider $tp,
                array $attempts,
            ) {
                parent::__construct($tp);
                $this->attempts = $attempts;
            }

            protected function createPdoConnection($dsn, $username, #[\SensitiveParameter] $password, $options): PDO
            {
                $entry = $this->attempts[$this->callIdx++] ?? null;
                if ($entry instanceof PDOException) {
                    throw $entry;
                }
                if ($entry instanceof PDO) {
                    return $entry;
                }
                throw new \RuntimeException('no attempt seeded at index '.($this->callIdx - 1));
            }
        };
    }

    private function mockConnectorThatThrows(PDOException $exception): IamPostgresConnector
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('iam-token-value');
        $tokenProvider->shouldReceive('credentialSnapshot')->andReturn([]);

        $pdo = Mockery::mock(PDO::class);

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $connector->shouldReceive('createPdoConnection')
            ->once()->andThrow($exception);
        $connector->shouldReceive('createPdoConnection')
            ->andReturn($pdo);

        return $connector;
    }

    private function makePdoException(string $sqlstate, string $message): PDOException
    {
        $exception = new PDOException($message);
        $exception->errorInfo = [$sqlstate, null, $message];

        return $exception;
    }

    private function iamConfig(): array
    {
        return [
            'host' => 'my-rds.cluster.us-east-1.rds.amazonaws.com',
            'port' => 5432,
            'database' => 'mydb',
            'username' => 'iam_user',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'us-east-1',
            'charset' => 'utf8',
        ];
    }
}
