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

        // Even though connection config has sslmode=prefer, the package forces verify-full
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
            'sslmode' => 'prefer', // should be overridden
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

    /**
     * @dataProvider postgresAuthRejectionScenarios
     */
    public function test_postgres_auth_rejection_logs_structured_warning(
        string $sqlstate,
        string $message,
    ): void {
        $connector = $this->mockConnectorThatThrows($this->makePdoException($sqlstate, $message));

        Log::spy();

        try {
            $connector->createConnection('pgsql:host=...', $this->iamConfig(), []);
            $this->fail('Expected PDOException to propagate.');
        } catch (PDOException) {
            // expected
        }

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(fn (string $msg) => $msg === 'iam-auth.rds-auth-rejected');
    }

    public static function postgresAuthRejectionScenarios(): array
    {
        return [
            'invalid_password (28P01)' => [
                '28P01',
                'SQLSTATE[28P01]: Invalid authorization specification: 7 FATAL: password authentication failed for user "iam_user"',
            ],
            'invalid_authorization_specification (28000)' => [
                '28000',
                'SQLSTATE[28000]: Invalid authorization specification: 7 FATAL: no pg_hba.conf entry for host "10.0.4.26", user "iam_user"',
            ],
        ];
    }

    public function test_postgres_non_auth_pdo_exception_does_not_log_warning(): void
    {
        // SQLSTATE 42501 = insufficient_privilege (Class 42 — access rule
        // violation, not Class 28). Authorization-adjacent but per-statement,
        // not a connection-time auth rejection.
        $connector = $this->mockConnectorThatThrows(
            $this->makePdoException('42501', "SQLSTATE[42501]: Insufficient privilege: 7 ERROR: permission denied for table users")
        );

        Log::spy();

        try {
            $connector->createConnection('pgsql:host=...', $this->iamConfig(), []);
        } catch (PDOException) {
            // expected
        }

        Log::shouldNotHaveReceived('warning',
            [Mockery::pattern('/rds-auth-rejected/'), Mockery::any()]);
    }

    private function mockConnectorThatThrows(PDOException $exception): IamPostgresConnector
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('iam-token-value');

        $connector = Mockery::mock(IamPostgresConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $connector->shouldReceive('createPdoConnection')->andThrow($exception);

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
