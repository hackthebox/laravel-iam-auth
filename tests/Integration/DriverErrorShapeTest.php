<?php

namespace Hackthebox\IamAuth\Tests\Integration;

use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Database\Connectors\Connector;
use Illuminate\Support\Facades\Log;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;
use PDOException;
use ReflectionMethod;

/**
 * Asserts the auth-rejection classifier against exceptions produced by a real server.
 *
 * The unit suite builds PDOException objects by hand, and a fabricated fixture cannot
 * disagree with the driver: no supported PostgreSQL emits the SQLSTATE 28P01 shape
 * those fixtures assert on. These tests take the exception from a connection a real
 * server actually rejected, across every supported engine version.
 *
 * Driven by the driver-shapes job in .github/workflows/tests.yml; skipped when unset.
 */
class DriverErrorShapeTest extends TestCase
{
    private string $driver;

    private string $host;

    private int $port;

    private string $database;

    private string $username;

    private string $password;

    protected function getPackageProviders($app): array
    {
        return [IamAuthServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $driver = getenv('IAM_AUTH_IT_DRIVER');

        if ($driver === false || $driver === '') {
            $this->markTestSkipped('IAM_AUTH_IT_DRIVER is not set; see the driver-shapes CI job.');
        }

        $this->driver = $driver;
        $this->host = (string) getenv('IAM_AUTH_IT_HOST');
        $this->port = (int) getenv('IAM_AUTH_IT_PORT');
        $this->database = (string) getenv('IAM_AUTH_IT_DATABASE');
        $this->username = (string) getenv('IAM_AUTH_IT_USERNAME');
        $this->password = (string) getenv('IAM_AUTH_IT_PASSWORD');
    }

    public function test_wrong_password_is_classified_as_auth_rejection(): void
    {
        $e = $this->connectExpectingFailure($this->dsn($this->database), $this->username, 'definitely-not-the-password');

        $this->assertTrue(
            $this->classify($e),
            'A real rejection must reach the fresh-credential retry path. Driver reported: '
            .json_encode($e->errorInfo),
        );
    }

    public function test_real_auth_rejection_is_not_treated_as_a_lost_connection(): void
    {
        $e = $this->connectExpectingFailure($this->dsn($this->database), $this->username, 'definitely-not-the-password');

        $connector = $this->makeConnector($this->createMock(RdsTokenProvider::class));
        $method = new ReflectionMethod($connector, 'causedByLostConnection');

        $this->assertFalse(
            $method->invoke($connector, $e),
            'Laravel must not retry an auth rejection with the same rejected token.',
        );
    }

    public function test_connection_refused_is_not_classified_as_auth_rejection(): void
    {
        $dsn = $this->driver === 'pgsql'
            ? "pgsql:host={$this->host};port=1;dbname={$this->database}"
            : "mysql:host={$this->host};port=1;dbname={$this->database}";

        $e = $this->connectExpectingFailure($dsn, $this->username, $this->password);

        $this->assertFalse(
            $this->classify($e),
            'A network failure must not invalidate credentials. Driver reported: '.json_encode($e->errorInfo),
        );
    }

    public function test_missing_database_is_not_classified_as_auth_rejection(): void
    {
        $e = $this->connectExpectingFailure($this->dsn('database_that_does_not_exist'), $this->username, $this->password);

        $this->assertFalse(
            $this->classify($e),
            'A missing database shares the 08006/7 envelope but is not an auth failure. Driver reported: '
            .json_encode($e->errorInfo),
        );
    }

    public function test_pam_rejection_is_classified_as_auth_rejection(): void
    {
        $this->requirePostgres();

        $pamUser = (string) getenv('IAM_AUTH_IT_PAM_USERNAME');

        if ($pamUser === '') {
            $this->markTestSkipped('IAM_AUTH_IT_PAM_USERNAME is not set.');
        }

        $e = $this->connectExpectingFailure($this->dsn($this->database), $pamUser, 'irrelevant');

        $this->assertStringContainsStringIgnoringCase(
            'PAM authentication failed',
            (string) ($e->errorInfo[2] ?? ''),
            'Expected the server to reject via PAM, as RDS IAM does.',
        );
        $this->assertTrue($this->classify($e), 'This is the exact shape reported in issue #17.');
    }

    /**
     * The acceptance criteria of issue #17, end to end against a real server: a
     * rejected credential is retried once with a freshly resolved one, and the
     * connection succeeds without the caller seeing an error.
     */
    public function test_connector_recovers_from_a_real_rejection_using_fresh_credentials(): void
    {
        $this->requirePostgres();

        Log::spy();

        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('credentialSnapshot')->andReturn([]);
        $tokenProvider->shouldReceive('getToken')
            ->once()->with($this->host, $this->port, $this->username, 'us-east-1')
            ->andReturn('a-stale-token');
        $tokenProvider->shouldReceive('getToken')
            ->once()->with($this->host, $this->port, $this->username, 'us-east-1', Mockery::on(fn ($f) => $f === true))
            ->andReturn($this->password);

        $connector = $this->makeConnector($tokenProvider);

        $pdo = $connector->createConnection($this->dsn($this->database), [
            'host' => $this->host,
            'port' => $this->port,
            'database' => $this->database,
            'username' => $this->username,
            'use_iam_auth' => true,
            'region' => 'us-east-1',
        ], []);

        $this->assertInstanceOf(PDO::class, $pdo);
        $this->assertSame('1', (string) $pdo->query('select 1')->fetchColumn());

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldNotHaveReceived('warning', ['iam-auth.rds-auth-rejected-retry-failed', Mockery::any()]);
    }

    private function requirePostgres(): void
    {
        if ($this->driver !== 'pgsql') {
            $this->markTestSkipped('PostgreSQL-specific behaviour.');
        }
    }

    private function dsn(string $database): string
    {
        $scheme = $this->driver === 'pgsql' ? 'pgsql' : 'mysql';

        return "{$scheme}:host={$this->host};port={$this->port};dbname={$database}";
    }

    private function connectExpectingFailure(string $dsn, string $username, string $password): PDOException
    {
        try {
            new PDO($dsn, $username, $password);
        } catch (PDOException $e) {
            return $e;
        }

        $this->fail("Expected the server to reject the connection: $dsn as $username");
    }

    private function classify(PDOException $e): bool
    {
        $connector = $this->makeConnector($this->createMock(RdsTokenProvider::class));

        return (new ReflectionMethod($connector, 'isAuthRejection'))->invoke($connector, $e);
    }

    private function makeConnector(RdsTokenProvider $tokenProvider): Connector
    {
        return match ($this->driver) {
            'pgsql' => new IamPostgresConnector($tokenProvider),
            'mariadb' => new IamMariaDbConnector($tokenProvider),
            default => new IamMySqlConnector($tokenProvider),
        };
    }
}
