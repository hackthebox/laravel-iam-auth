<?php

namespace Hackthebox\IamAuth\Tests;

use Aws\Credentials\Credentials;
use Aws\Rds\AuthTokenGenerator;
use GuzzleHttp\Promise\Create;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Mockery;
use Orchestra\Testbench\TestCase;
use RuntimeException;

class RdsTokenProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            \Aws\Laravel\AwsServiceProvider::class,
            IamAuthServiceProvider::class,
        ];
    }

    /**
     * Create a RdsTokenProvider with a mocked AuthTokenGenerator.
     * The credential provider is a callable that returns a promise
     * wrapping static credentials.
     */
    private function mockProvider(string $tokenValue = 'generated-iam-token', bool $shouldFail = false): RdsTokenProvider
    {
        $credentials = new Credentials('test-key', 'test-secret', 'test-token', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($credentials);

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $generator = Mockery::mock(AuthTokenGenerator::class);

        if ($shouldFail) {
            $generator->shouldReceive('createToken')
                ->andThrow(new \Exception('STS credentials not found'));
        } else {
            $generator->shouldReceive('createToken')
                ->andReturn($tokenValue);
        }

        $provider->shouldReceive('createAuthTokenGenerator')
            ->andReturn($generator);

        return $provider;
    }

    public function test_generates_token_via_aws_sdk(): void
    {
        $provider = $this->mockProvider();

        $token = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');

        $this->assertSame('generated-iam-token', $token);
    }

    public function test_caches_token_in_laravel_cache_store(): void
    {
        config(['iam-auth.cache_store' => 'file']);

        $credentials = new Credentials('test-key', 'test-secret', 'test-token', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($credentials);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')
            ->once()
            ->andReturn('generated-iam-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $provider->shouldReceive('createAuthTokenGenerator')
            ->andReturn($generator);

        $token1 = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');
        $token2 = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');

        $this->assertSame('generated-iam-token', $token1);
        $this->assertSame($token1, $token2);

        $fingerprint = substr(hash('sha256', 'test-key'.'test-token'), 0, 16);
        $cached = cache()->store('file')->get(
            "rds_iam:my-rds.cluster.us-east-1.rds.amazonaws.com:3306:app_user:us-east-1:$fingerprint"
        );
        $this->assertSame('generated-iam-token', $cached);
    }

    public function test_skips_laravel_cache_when_store_is_null(): void
    {
        cache()->store('file')->flush();
        config(['iam-auth.cache_store' => null]);

        $provider = $this->mockProvider();

        $token = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');

        $this->assertSame('generated-iam-token', $token);

        $cached = cache()->store('file')->get('rds_iam:my-rds.cluster.us-east-1.rds.amazonaws.com:3306:app_user:us-east-1');
        $this->assertNull($cached);
    }

    public function test_throws_on_database_cache_store(): void
    {
        config([
            'iam-auth.cache_store' => 'db_cache',
            'cache.stores.db_cache' => ['driver' => 'database', 'table' => 'cache'],
        ]);

        $provider = $this->mockProvider();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("cannot use the 'db_cache' cache store");

        $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');
    }

    public function test_throws_on_dynamodb_cache_store(): void
    {
        config([
            'iam-auth.cache_store' => 'dynamo',
            'cache.stores.dynamo' => ['driver' => 'dynamodb', 'table' => 'cache'],
        ]);

        $provider = $this->mockProvider();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("cannot use the 'dynamo' cache store");

        $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');
    }

    public function test_rotated_credentials_generate_fresh_token(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $credsA = new Credentials('key-A', 'secret-A', 'token-A', time() + 3600);
        $credsB = new Credentials('key-B', 'secret-B', 'token-B', time() + 3600);
        $queue = [$credsA, $credsA, $credsB];
        $credentialProvider = function () use (&$queue) {
            return Create::promiseFor(array_shift($queue));
        };

        $signCount = 0;
        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')
            ->andReturnUsing(function () use (&$signCount) {
                return 'token-'.(++$signCount);
            });

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);

        $t1 = $provider->getToken('host', 3306, 'user', 'region');
        $t2 = $provider->getToken('host', 3306, 'user', 'region');
        $t3 = $provider->getToken('host', 3306, 'user', 'region');

        $this->assertSame($t1, $t2, 'Same credentials should reuse the cached token.');
        $this->assertNotSame($t1, $t3, 'Rotated credentials must invalidate the cached token.');
        $this->assertSame(2, $signCount, 'Token must be signed once per distinct credential set.');
    }

    public function test_cache_key_includes_credential_fingerprint(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $creds = new Credentials('AKIATEST', 'secret', 'session-token-value', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->once()->andReturn('generated-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);

        $provider->getToken('host', 3306, 'user', 'region');

        $expectedFingerprint = substr(hash('sha256', 'AKIATEST'.'session-token-value'), 0, 16);
        $expectedKey = "rds_iam:host:3306:user:region:$expectedFingerprint";

        $this->assertSame('generated-token', cache()->store('file')->get($expectedKey));
    }

    public function test_apcu_cache_key_includes_credential_fingerprint(): void
    {
        $creds = new Credentials('AKIATEST', 'secret', 'session-token-value', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->andReturn('generated-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);
        $provider->shouldReceive('apcuAvailable')->andReturn(true);

        $capturedKey = null;
        $provider->shouldReceive('apcuEntry')
            ->once()
            ->andReturnUsing(function ($key, $gen) use (&$capturedKey) {
                $capturedKey = $key;
                return $gen();
            });

        $provider->getToken('host', 3306, 'user', 'region');

        $expectedFingerprint = substr(hash('sha256', 'AKIATEST'.'session-token-value'), 0, 16);
        $this->assertSame("rds_iam:host:3306:user:region:$expectedFingerprint", $capturedKey);
    }

    public function test_apcu_rotated_credentials_use_distinct_cache_keys(): void
    {
        $credsA = new Credentials('key-A', 'secret-A', 'token-A', time() + 3600);
        $credsB = new Credentials('key-B', 'secret-B', 'token-B', time() + 3600);
        $queue = [$credsA, $credsB];
        $credentialProvider = function () use (&$queue) {
            return Create::promiseFor(array_shift($queue));
        };

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->andReturn('signed');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);
        $provider->shouldReceive('apcuAvailable')->andReturn(true);

        $keys = [];
        $provider->shouldReceive('apcuEntry')
            ->andReturnUsing(function ($key, $gen) use (&$keys) {
                $keys[] = $key;
                return $gen();
            });

        $provider->getToken('host', 3306, 'user', 'region');
        $provider->getToken('host', 3306, 'user', 'region');

        $this->assertCount(2, $keys);
        $this->assertNotSame($keys[0], $keys[1]);
    }

    public function test_wraps_token_generation_failure_with_context(): void
    {
        $provider = $this->mockProvider(shouldFail: true);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'Failed to generate RDS IAM auth token for app_user@my-rds.cluster.us-east-1.rds.amazonaws.com:3306 in region us-east-1: STS credentials not found'
        );

        $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');
    }
}
