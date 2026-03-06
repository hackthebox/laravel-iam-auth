<?php

namespace Hackthebox\RdsIamAuth\Tests\Connectors;

use Hackthebox\RdsIamAuth\Connectors\RdsIamPostgresConnector;
use Hackthebox\RdsIamAuth\RdsAuthTokenProvider;
use Hackthebox\RdsIamAuth\RdsIamAuthServiceProvider;
use Illuminate\Database\Connectors\PostgresConnector;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;

class RdsIamPostgresConnectorTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [RdsIamAuthServiceProvider::class];
    }

    public function test_extends_postgres_connector(): void
    {
        $this->assertTrue(is_subclass_of(RdsIamPostgresConnector::class, PostgresConnector::class));
    }

    public function test_injects_iam_token_when_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com', 5432, 'app', 'us-east-1')
            ->andReturn('iam-token-value');

        $connector = Mockery::mock(RdsIamPostgresConnector::class, [$tokenProvider])
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
        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(RdsIamPostgresConnector::class, [$tokenProvider])
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
        config(['rds-iam-auth.pgsql_sslmode' => 'verify-full']);

        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(RdsIamPostgresConnector::class, [$tokenProvider])
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
        config(['rds-iam-auth.ssl_ca_path' => '/path/to/ca-bundle.pem']);

        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('token');

        $connector = Mockery::mock(RdsIamPostgresConnector::class, [$tokenProvider])
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

    public function test_skips_iam_when_not_enabled(): void
    {
        $tokenProvider = Mockery::mock(RdsAuthTokenProvider::class);
        $tokenProvider->shouldNotReceive('getToken');

        $connector = Mockery::mock(RdsIamPostgresConnector::class, [$tokenProvider])
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
}
