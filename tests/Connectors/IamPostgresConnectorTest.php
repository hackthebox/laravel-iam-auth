<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

use Aws\Exception\CredentialsException;
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
use ReflectionMethod;
use RuntimeException;
use SensitiveParameter;

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

    /**
     * Covers the forward-compatible class 28 guard, not observed driver behaviour.
     *
     * No supported engine emits SQLSTATE class 28 while establishing a connection, so
     * this fixture is synthetic by construction; DriverErrorShapeTest is what asserts
     * against the shapes drivers really produce. The guard earns its place only if a
     * future PDO stops flattening the server SQLSTATE to 08006, which would otherwise
     * bypass the message matching in isPgsqlAuthRejection().
     */
    public function test_class_28_sqlstate_28p01_is_treated_as_an_auth_rejection(): void
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

    public function test_class_28_sqlstate_28000_is_treated_as_an_auth_rejection(): void
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

    public function test_retry_succeeds_after_auth_rejection_08006_pam(): void
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
            attempts: [
                $this->pgConnectFailure('FATAL:  PAM authentication failed for user "iam_user"'),
                $this->createMock(PDO::class),
            ],
        );

        $pdo = $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
        $this->assertNotNull($pdo);

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldNotHaveReceived('warning', ['iam-auth.rds-auth-rejected-retry-failed', Mockery::any()]);
    }

    public function test_retry_failure_after_pam_auth_rejection_logs_retry_failed_and_propagates_second_exception(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->method('getToken')->willReturn('token');

        $first = $this->pgConnectFailure('FATAL:  PAM authentication failed for user "iam_user"');
        $second = $this->pgConnectFailure('FATAL:  PAM authentication failed for user "iam_user" (retry second failure)');

        $connector = $this->makeConnector($tokenProvider, attempts: [$first, $second]);

        try {
            $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException $e) {
            $this->assertStringContainsString('retry second failure', $e->getMessage());
        }

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected-retry-failed', Mockery::any())->once();
    }

    public function test_retry_succeeds_after_password_authentication_failed(): void
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
            attempts: [
                $this->pgConnectFailure('FATAL:  password authentication failed for user "iam_user"'),
                $this->createMock(PDO::class),
            ],
        );

        $pdo = $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
        $this->assertNotNull($pdo);

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
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

    /**
     * Real PostgreSQL 14+ wording. Shares the 08006/7 envelope with an auth rejection,
     * so only the message keeps it off the credential-refresh path.
     *
     * Seeded twice because Laravel's own lost-connection retry may legitimately fire
     * for a refused connection, and which releases recognise this wording has changed
     * over time. Either way the token must be signed once: no forced refresh.
     */
    public function test_connection_refused_does_not_trigger_retry(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->once())->method('getToken')->willReturn('token');

        $refused = fn () => $this->pgConnectFailure(
            "Connection refused\n\tIs the server running on that host and accepting TCP/IP connections?"
        );

        $connector = $this->makeConnector($tokenProvider, attempts: [$refused(), $refused()]);

        try {
            $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException) {
        }

        Log::shouldNotHaveReceived('warning');
    }

    /**
     * Only the two mechanisms a fresh IAM token can satisfy count. The other pg_hba
     * methods produce the same "<method> authentication failed for user" wording, and
     * re-signing a token fixes none of them, so widening the match to a bare
     * "authentication failed" would spend a credential invalidation and an STS round
     * trip on every one of them.
     */
    public function test_non_iam_authentication_methods_do_not_trigger_retry(): void
    {
        Log::spy();

        foreach (['Ident', 'Peer', 'GSSAPI', 'LDAP', 'RADIUS'] as $method) {
            $tokenProvider = $this->createMock(RdsTokenProvider::class);
            $tokenProvider->expects($this->once())->method('getToken')->willReturn('token');

            $connector = $this->makeConnector($tokenProvider, attempts: [
                $this->pgConnectFailure("FATAL:  $method authentication failed for user \"iam_user\""),
            ]);

            try {
                $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
                $this->fail("expected PDOException for $method");
            } catch (PDOException) {
            }
        }

        Log::shouldNotHaveReceived('warning');
    }

    public function test_missing_database_does_not_trigger_retry(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->once())->method('getToken')->willReturn('token');

        $connector = $this->makeConnector($tokenProvider, attempts: [
            $this->pgConnectFailure('FATAL:  database "hackthebox" does not exist'),
        ]);

        try {
            $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException) {
        }

        Log::shouldNotHaveReceived('warning');
    }

    /**
     * The auth wording only counts inside the 08006/7 envelope pdo_pgsql produces at
     * connect time, so a different driver code stays on the normal failure path.
     */
    public function test_auth_wording_under_a_different_driver_code_does_not_trigger_retry(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->once())->method('getToken')->willReturn('token');

        $err = new PDOException('SQLSTATE[08006] [99] password authentication failed for user "iam_user"');
        $err->errorInfo = ['08006', 99, 'password authentication failed for user "iam_user"'];

        $connector = $this->makeConnector($tokenProvider, attempts: [$err]);

        try {
            $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException) {
        }

        Log::shouldNotHaveReceived('warning');
    }

    /**
     * The wording is only trusted inside the envelope pdo_pgsql produces at connect
     * time. A different SQLSTATE carrying the same words is some other failure.
     */
    public function test_auth_wording_under_a_different_sqlstate_does_not_trigger_retry(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->once())->method('getToken')->willReturn('token');

        $err = new PDOException('SQLSTATE[08P01] [7] password authentication failed for user "iam_user"');
        $err->errorInfo = ['08P01', 7, 'FATAL:  password authentication failed for user "iam_user"'];

        $connector = $this->makeConnector($tokenProvider, attempts: [$err]);

        try {
            $connector->createConnection('pgsql:host=h', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException) {
        }

        Log::shouldNotHaveReceived('warning');
    }

    /**
     * errorInfo[2] is the server's own text; getMessage() is PDO's rendering of it and
     * is only a fallback. Anything wrapping the exception must not change the verdict.
     */
    public function test_driver_message_is_preferred_over_the_exception_message(): void
    {
        Log::spy();

        $tokenProvider = $this->createMock(RdsTokenProvider::class);
        $tokenProvider->expects($this->exactly(2))->method('getToken')->willReturn('token');

        $err = new PDOException('an opaque wrapper message');
        $err->errorInfo = ['08006', 7, 'FATAL:  PAM authentication failed for user "iam_user"'];

        $connector = $this->makeConnector($tokenProvider, attempts: [$err, $this->createMock(PDO::class)]);

        $this->assertNotNull($connector->createConnection('pgsql:host=h', $this->iamConfig(), []));

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
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
                throw new CredentialsException('agent unreachable');
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
        } catch (CredentialsException) {
        }

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.rds-auth-rejected', Mockery::any())->once();
        Log::shouldNotHaveReceived('warning', ['iam-auth.rds-auth-rejected-retry-failed', Mockery::any()]);
    }

    public function test_caused_by_lost_connection_returns_false_for_auth_rejection(): void
    {
        $connector = $this->makeConnector(
            $this->createMock(RdsTokenProvider::class),
            attempts: [],
        );

        $ref = new ReflectionMethod($connector, 'causedByLostConnection');
        $ref->setAccessible(true);

        $authRejection = $this->pgAuthRejection('28P01');
        $this->assertFalse($ref->invoke($connector, $authRejection));

        $pamRejection = $this->pgConnectFailure('FATAL:  PAM authentication failed for user "iam_user"');
        $this->assertFalse($ref->invoke($connector, $pamRejection));
    }

    public function test_caused_by_lost_connection_delegates_to_parent_for_non_auth(): void
    {
        $connector = $this->makeConnector(
            $this->createMock(RdsTokenProvider::class),
            attempts: [],
        );

        $ref = new ReflectionMethod($connector, 'causedByLostConnection');
        $ref->setAccessible(true);

        $lostConnection = new PDOException('SQLSTATE[08006] [7] could not connect to server: Connection refused Is the server running on host');
        $lostConnection->errorInfo = ['08006', 7, 'server closed the connection unexpectedly'];
        $this->assertTrue($ref->invoke($connector, $lostConnection));

        $unrelated = new PDOException('permission denied');
        $unrelated->errorInfo = ['42501', 7, 'permission denied for table users'];
        $this->assertFalse($ref->invoke($connector, $unrelated));
    }

    private function pgAuthRejection(string $sqlstate = '28000', string $msg = 'invalid password'): PDOException
    {
        $e = new PDOException("SQLSTATE[$sqlstate]: $msg");
        $e->errorInfo = [$sqlstate, 7, $msg];
        return $e;
    }

    /**
     * The exception shape pdo_pgsql actually produces at connect time.
     *
     * A failed PQconnectdb yields no PGresult, so libpq cannot supply a SQLSTATE and
     * the driver substitutes 08006 with PGRES_FATAL_ERROR (7) for every connect-time
     * failure, discarding the server's real SQLSTATE. Verified on PostgreSQL 14-18.
     */
    private function pgConnectFailure(string $serverMessage): PDOException
    {
        $driverMessage = 'connection to server at "db.example" (10.0.107.200), port 5432 failed: '.$serverMessage;

        $e = new PDOException("SQLSTATE[08006] [7] $driverMessage");
        $e->errorInfo = ['08006', 7, $driverMessage];

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
