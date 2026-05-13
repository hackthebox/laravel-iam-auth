<?php

namespace Hackthebox\IamAuth\Tests\Connectors;

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

    /**
     * @dataProvider authRejectionScenarios
     */
    public function test_auth_rejection_logs_structured_warning(
        ?string $sqlstate,
        ?int $driverCode,
        string $message,
    ): void {
        $connector = $this->mockConnectorThatThrows($this->makePdoException($sqlstate, $driverCode, $message));

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

    public static function authRejectionScenarios(): array
    {
        return [
            'postgres invalid_password (28P01)' => [
                '28P01', 7,
                'SQLSTATE[28P01]: Invalid authorization specification: 7 FATAL: password authentication failed',
            ],
            'postgres invalid_authorization (28000)' => [
                '28000', 7,
                'SQLSTATE[28000]: Invalid authorization specification: 7 FATAL: no pg_hba.conf entry',
            ],
            'mysql access denied (1045 / HY000)' => [
                'HY000', 1045,
                "SQLSTATE[HY000] [1045] Access denied for user 'iam_user'@'10.0.4.26' (using password: YES)",
            ],
        ];
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

        Log::shouldNotHaveReceived('warning',
            [Mockery::pattern('/rds-auth-rejected/'), Mockery::any()]);
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
