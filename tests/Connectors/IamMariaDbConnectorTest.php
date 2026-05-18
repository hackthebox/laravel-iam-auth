<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

use Aws\Credentials\Credentials;
use Hackthebox\IamAuth\AwsCredentialCache;
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
        $connector = $this->mockConnectorThatThrows($this->makePdoException(
            'HY000', 1045,
            "SQLSTATE[HY000] [1045] Access denied for user 'iam_user'@'10.0.4.26' (using password: YES)",
        ));

        Log::spy();

        try {
            $connector->createConnection('dsn', $this->iamConfig(), []);
            $this->fail('Expected PDOException to propagate.');
        } catch (PDOException) {
            // expected
        }

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(fn (string $msg, array $ctx) => $msg === 'iam-auth.rds-auth-rejected');
    }

    public function test_auth_rejection_warning_includes_credentials_from_laravel_cache(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $creds = new Credentials('AKIAEXAMPLE12345', 'secret', 'session-token', time() + 3600);
        cache()->store('file')->put(AwsCredentialCache::CACHE_KEY, $creds, 3600);

        $connector = $this->mockConnectorThatThrows($this->makePdoException(
            'HY000', 1045, "SQLSTATE[HY000] [1045] Access denied for user 'iam_user'@'10.0.4.26'",
        ));

        Log::spy();

        try {
            $connector->createConnection('dsn', $this->iamConfig(), []);
        } catch (PDOException) {
            // expected
        }

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
        // SQLSTATE 42000 / native code 1064 = MySQL syntax error. Not an
        // auth rejection; the package must propagate it without firing
        // the rds-auth-rejected warning.
        $connector = $this->mockConnectorThatThrows(
            $this->makePdoException('42000', 1064, "SQLSTATE[42000]: Syntax error: 1064 You have an error in your SQL syntax")
        );

        Log::spy();

        try {
            $connector->createConnection('dsn', $this->iamConfig(), []);
        } catch (PDOException) {
            // expected
        }

        Log::shouldNotHaveReceived('warning');
    }

    private function mockConnectorThatThrows(PDOException $exception): IamMariaDbConnector
    {
        $tokenProvider = Mockery::mock(RdsTokenProvider::class);
        $tokenProvider->shouldReceive('getToken')->andReturn('iam-token-value');

        $connector = Mockery::mock(IamMariaDbConnector::class, [$tokenProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $connector->shouldReceive('createPdoConnection')->andThrow($exception);

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
}
