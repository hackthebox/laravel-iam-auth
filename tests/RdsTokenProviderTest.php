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

        $cached = cache()->store('file')->get('rds_iam:my-rds.cluster.us-east-1.rds.amazonaws.com:3306:app_user:us-east-1');
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
