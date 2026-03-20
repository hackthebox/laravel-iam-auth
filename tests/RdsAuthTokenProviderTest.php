<?php

namespace Hackthebox\RdsIamAuth\Tests;

use Aws\Rds\AuthTokenGenerator;
use Hackthebox\RdsIamAuth\RdsAuthTokenProvider;
use Hackthebox\RdsIamAuth\RdsIamAuthServiceProvider;
use Mockery;
use Orchestra\Testbench\TestCase;
use RuntimeException;

class RdsAuthTokenProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [RdsIamAuthServiceProvider::class];
    }

    private function mockProvider(AuthTokenGenerator $generator = null): RdsAuthTokenProvider&Mockery\MockInterface
    {
        if ($generator === null) {
            $generator = Mockery::mock(AuthTokenGenerator::class);
            $generator->shouldReceive('createToken')
                ->andReturn('generated-iam-token');
        }

        $provider = Mockery::mock(RdsAuthTokenProvider::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $provider->shouldReceive('createTokenGenerator')
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
        config(['rds-iam-auth.cache_store' => 'file']);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')
            ->once()
            ->andReturn('generated-iam-token');

        $provider = $this->mockProvider($generator);

        $token1 = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');
        $token2 = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');

        $this->assertSame('generated-iam-token', $token1);
        $this->assertSame($token1, $token2);

        // Verify it's actually in the cache store
        $cached = cache()->store('file')->get('rds_iam:my-rds.cluster.us-east-1.rds.amazonaws.com:3306:app_user:us-east-1');
        $this->assertSame('generated-iam-token', $cached);
    }

    public function test_skips_laravel_cache_when_store_is_null(): void
    {
        cache()->store('file')->flush();
        config(['rds-iam-auth.cache_store' => null]);

        $provider = $this->mockProvider();

        $token = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');

        $this->assertSame('generated-iam-token', $token);

        // Should not be in any cache
        $cached = cache()->store('file')->get('rds_iam:my-rds.cluster.us-east-1.rds.amazonaws.com:3306:app_user:us-east-1');
        $this->assertNull($cached);
    }

    public function test_throws_on_database_cache_store(): void
    {
        config([
            'rds-iam-auth.cache_store' => 'db_cache',
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
            'rds-iam-auth.cache_store' => 'dynamo',
            'cache.stores.dynamo' => ['driver' => 'dynamodb', 'table' => 'cache'],
        ]);

        $provider = $this->mockProvider();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("cannot use the 'dynamo' cache store");

        $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');
    }

    private function resolveCredentialProviderFor(string $name): callable
    {
        config(['rds-iam-auth.credential_provider' => $name]);

        $provider = new class extends RdsAuthTokenProvider
        {
            public function exposeCredentialProvider(): callable
            {
                return $this->resolveCredentialProvider();
            }
        };

        return $provider->exposeCredentialProvider();
    }

    /**
     * @dataProvider validCredentialProviderNames
     */
    public function test_resolves_all_supported_credential_providers(string $name): void
    {
        $result = $this->resolveCredentialProviderFor($name);
        $this->assertIsCallable($result);
    }

    public static function validCredentialProviderNames(): array
    {
        return [
            'default' => ['default'],
            'environment' => ['environment'],
            'ecs' => ['ecs'],
            'web_identity' => ['web_identity'],
            'instance_profile' => ['instance_profile'],
            'sso' => ['sso'],
            'ini' => ['ini'],
        ];
    }

    public function test_throws_on_unsupported_credential_provider(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Unsupported RDS IAM credential provider 'banana'");

        $this->resolveCredentialProviderFor('banana');
    }

    public function test_wraps_token_generation_failure_with_context(): void
    {
        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')
            ->andThrow(new \Exception('STS credentials not found'));

        $provider = $this->mockProvider($generator);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(
            'Failed to generate RDS IAM auth token for app_user@my-rds.cluster.us-east-1.rds.amazonaws.com:3306 in region us-east-1: STS credentials not found'
        );

        $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');
    }
}
