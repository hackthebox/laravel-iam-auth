<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

use Aws\CacheInterface;
use Aws\Credentials\Credentials;
use Hackthebox\IamAuth\Cache\AwsCredentialCacheStore;
use Hackthebox\IamAuth\Cache\CachedCredentialProvider;
use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Database\Connectors\MariaDbConnector;
use Illuminate\Support\Facades\Log;
use Mockery;
use Orchestra\Testbench\TestCase;
use PDO;
use PDOException;

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

    public function test_mysql_1045_logs_structured_warning(): void
    {
        // Message intentionally omits the "for user" suffix that matches Laravel's
        // DetectsLostConnections list, which would otherwise silently swallow the
        // first throw via tryAgainIfCausedByLostConnection before our trait sees it.
        $connector = $this->mockConnectorThatThrows($this->makePdoException(
            'HY000', 1045,
            "SQLSTATE[HY000] [1045] Access denied (using password: YES)",
        ));

        Log::spy();

        $connector->createConnection('dsn', $this->iamConfig(), []);

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(fn (string $msg, array $ctx) => $msg === 'iam-auth.rds-auth-rejected');
    }

    public function test_auth_rejection_warning_includes_credentials_from_cache(): void
    {
        $creds = new Credentials('AKIAEXAMPLE12345', 'secret', 'session-token', time() + 3600);

        $cacheStore = $this->stubCacheStore($creds);
        $this->app->instance(CacheInterface::class, $cacheStore);
        $this->app->forgetInstance(CachedCredentialProvider::class);

        $tokenProvider = $this->app->make(RdsTokenProvider::class);

        $rejection = $this->makePdoException('HY000', 1045, "SQLSTATE[HY000] [1045] Access denied");
        $connector = $this->makeConnector($tokenProvider, attempts: [$rejection, $this->createMock(PDO::class)]);

        Log::spy();

        $connector->createConnection('dsn', $this->iamConfig(), []);

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(function (string $msg, array $ctx) {
                return $msg === 'iam-auth.rds-auth-rejected'
                    && $ctx['cred_present'] === true
                    && $ctx['cred_access_key_prefix'] === 'AKIAEXAM'
                    && is_int($ctx['cred_expires_in_s']);
            });
    }

    public function test_non_auth_pdo_exception_does_not_log_warning(): void
    {
        $connector = $this->mockConnectorThatThrows(
            $this->makePdoException('42000', 1064, "SQLSTATE[42000]: Syntax error: 1064 You have an error in your SQL syntax")
        );

        Log::spy();

        try {
            $connector->createConnection('dsn', $this->iamConfig(), []);
        } catch (PDOException) {
        }

        Log::shouldNotHaveReceived('warning');
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
            attempts: [$this->mariaAuthRejection(), $this->createMock(PDO::class)],
        );

        $pdo = $connector->createConnection('mysql:host=h;dbname=d', $this->iamConfig(), []);
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

        $first = $this->mariaAuthRejection('first');
        $second = $this->mariaAuthRejection('second');

        $connector = $this->makeConnector($tokenProvider, attempts: [$first, $second]);

        try {
            $connector->createConnection('mysql:host=h;dbname=d', $this->iamConfig(), []);
            $this->fail('expected PDOException');
        } catch (PDOException $e) {
            $this->assertSame('second', $e->getMessage());
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
        $networkErr->errorInfo = ['HY000', 2002, 'connect timeout'];

        $connector = $this->makeConnector($tokenProvider, attempts: [$networkErr]);

        $this->expectException(PDOException::class);
        $connector->createConnection('mysql:host=h;dbname=d', $this->iamConfig(), []);

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
            attempts: [$this->mariaAuthRejection()],
        );

        try {
            $connector->createConnection('mysql:host=h;dbname=d', $this->iamConfig(), []);
            $this->fail('expected CredentialsException');
        } catch (\Aws\Exception\CredentialsException) {
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

        $ref = new \ReflectionMethod($connector, 'causedByLostConnection');
        $ref->setAccessible(true);

        $authRejection = $this->mariaAuthRejection();
        $this->assertFalse($ref->invoke($connector, $authRejection));
    }

    public function test_caused_by_lost_connection_delegates_to_parent_for_non_auth(): void
    {
        $connector = $this->makeConnector(
            $this->createMock(RdsTokenProvider::class),
            attempts: [],
        );

        $ref = new \ReflectionMethod($connector, 'causedByLostConnection');
        $ref->setAccessible(true);

        $lostConnection = new PDOException('SQLSTATE[HY000] [2006] MySQL server has gone away');
        $lostConnection->errorInfo = ['HY000', 2006, 'MySQL server has gone away'];
        $this->assertTrue($ref->invoke($connector, $lostConnection));

        $unrelated = new PDOException('Table not found');
        $unrelated->errorInfo = ['42S02', 1146, 'Table not found'];
        $this->assertFalse($ref->invoke($connector, $unrelated));
    }

    private function mariaAuthRejection(string $msg = 'access denied'): PDOException
    {
        $e = new PDOException($msg);
        $e->errorInfo = ['HY000', 1045, $msg];
        return $e;
    }

    private function makeConnector(
        RdsTokenProvider $tokenProvider,
        array $attempts,
    ): IamMariaDbConnector {
        return new class($tokenProvider, $attempts) extends IamMariaDbConnector {
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

    private function mockConnectorThatThrows(PDOException $exception): IamMariaDbConnector
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('iam-token-value');
        $tokenProvider->shouldReceive('credentialSnapshot')->andReturn([]);

        $pdo = Mockery::mock(PDO::class);

        $connector = Mockery::mock(IamMariaDbConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $connector->shouldReceive('createPdoConnection')
            ->once()->andThrow($exception);
        $connector->shouldReceive('createPdoConnection')
            ->andReturn($pdo);

        return $connector;
    }

    private function makePdoException(?string $sqlstate, ?int $driverCode, string $message): PDOException
    {
        $exception = new PDOException($message);
        $exception->errorInfo = [$sqlstate, $driverCode, $message];

        return $exception;
    }

    private function iamConfig(): array
    {
        return [
            'host' => 'my-rds.cluster.eu-central-1.rds.amazonaws.com',
            'port' => 3306,
            'username' => 'iam_user',
            'password' => '',
            'use_iam_auth' => true,
            'region' => 'eu-central-1',
        ];
    }

    private function stubCacheStore(Credentials $seed): AwsCredentialCacheStore
    {
        return new class($seed) extends AwsCredentialCacheStore {
            public function __construct(private Credentials $seed)
            {
            }

            protected function apcuAvailable(): bool
            {
                return false;
            }

            protected function cacheStoreName(): ?string
            {
                return 'iam-auth-stub';
            }

            public function get($key)
            {
                return $this->seed;
            }

            public function peek(string $key): ?\Aws\Credentials\CredentialsInterface
            {
                return $this->seed;
            }

            public function set($key, $value, $ttl = 0): void
            {
            }

            public function remove($key): void
            {
            }
        };
    }
}
