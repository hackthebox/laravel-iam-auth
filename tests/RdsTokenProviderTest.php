<?php

namespace Hackthebox\IamAuth\Tests;

use Aws\Credentials\Credentials;
use Aws\Credentials\CredentialsInterface;
use Aws\Rds\AuthTokenGenerator;
use GuzzleHttp\Promise\Create;
use Hackthebox\IamAuth\AwsCredentialCache;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Support\Facades\Log;
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
        cache()->store('file')->flush();

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

    public function test_laravel_cache_stores_structured_entry_with_sig_kid(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $creds = new Credentials('AKIATEST', 'secret', 'session-token-value', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->once()->andReturn('signed-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);

        $provider->getToken('my-host', 3306, 'user', 'us-east-1');

        $cached = cache()->store('file')->get('rds_iam:my-host:3306:user:us-east-1');

        $expectedSigKid = substr(hash('sha256', 'AKIATEST'.'session-token-value'), 0, 16);
        $this->assertIsArray($cached);
        $this->assertSame('signed-token', $cached['token']);
        $this->assertSame($expectedSigKid, $cached['sig_kid']);
        $this->assertArrayHasKey('signed_at', $cached);
    }

    public function test_apcu_caches_structured_entry_with_sig_kid(): void
    {
        $creds = new Credentials('AKIATEST', 'secret', 'session-token-value', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->once()->andReturn('signed-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);
        $provider->shouldReceive('apcuAvailable')->andReturn(true);

        $stored = null;
        $provider->shouldReceive('apcuEntry')
            ->once()
            ->andReturnUsing(function ($key, $gen) use (&$stored) {
                $stored = $gen();
                return $stored;
            });

        $token = $provider->getToken('my-host', 3306, 'user', 'us-east-1');

        $expectedSigKid = substr(hash('sha256', 'AKIATEST'.'session-token-value'), 0, 16);
        $this->assertSame('signed-token', $token);
        $this->assertIsArray($stored);
        $this->assertSame('signed-token', $stored['token']);
        $this->assertSame($expectedSigKid, $stored['sig_kid']);
        $this->assertArrayHasKey('signed_at', $stored);
    }

    public function test_apcu_mismatched_sig_kid_triggers_regeneration(): void
    {
        $currentCreds = new Credentials('key-B', 'secret-B', 'token-B', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($currentCreds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->once()->andReturn('fresh-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);
        $provider->shouldReceive('apcuAvailable')->andReturn(true);

        $staleEntry = [
            'token' => 'stale-token',
            'sig_kid' => substr(hash('sha256', 'old-key'.'old-token'), 0, 16),
            'signed_at' => time() - 60,
        ];
        $provider->shouldReceive('apcuEntry')->andReturn($staleEntry);

        $stored = null;
        $provider->shouldReceive('apcuStore')
            ->once()
            ->andReturnUsing(function ($key, $value) use (&$stored) {
                $stored = $value;
            });

        $token = $provider->getToken('host', 3306, 'user', 'region');

        $this->assertSame('fresh-token', $token);
        $this->assertIsArray($stored);
        $this->assertSame('fresh-token', $stored['token']);
        $this->assertSame(substr(hash('sha256', 'key-B'.'token-B'), 0, 16), $stored['sig_kid']);
    }

    public function test_apcu_matched_sig_kid_returns_cached_token_without_regeneration(): void
    {
        $creds = new Credentials('K', 's', 'sess', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldNotReceive('createToken');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);
        $provider->shouldReceive('apcuAvailable')->andReturn(true);

        $sigKid = substr(hash('sha256', 'Ksess'), 0, 16);
        $cachedEntry = ['token' => 'cached-token', 'sig_kid' => $sigKid, 'signed_at' => time() - 30];
        $provider->shouldReceive('apcuEntry')->once()->andReturn($cachedEntry);
        $provider->shouldNotReceive('apcuStore');

        $token = $provider->getToken('host', 3306, 'user', 'region');

        $this->assertSame('cached-token', $token);
    }

    public function test_apcu_legacy_non_array_entry_is_discarded_and_regenerated(): void
    {
        $creds = new Credentials('K', 's', 'sess', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->once()->andReturn('fresh-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);
        $provider->shouldReceive('apcuAvailable')->andReturn(true);

        $provider->shouldReceive('apcuEntry')->andReturn('legacy-plain-string-token');
        $provider->shouldReceive('apcuStore')->once();

        $token = $provider->getToken('host', 3306, 'user', 'region');

        $this->assertSame('fresh-token', $token);
    }

    public function test_cache_miss_with_no_cached_credentials_signs_without_exception(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $freshCreds = new Credentials('fresh-K', 'fresh-s', 'fresh-sess', time() + 3600);
        $providerCalls = 0;
        $credentialProvider = function () use (&$providerCalls, $freshCreds) {
            $providerCalls++;

            return Create::promiseFor($freshCreds);
        };

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->once()->andReturn('signed-fresh');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);

        $token = $provider->getToken('host', 3306, 'user', 'region');

        $this->assertSame('signed-fresh', $token);
        $this->assertGreaterThanOrEqual(1, $providerCalls,
            'Credential provider must be called when no cached credentials exist.');
    }

    public function test_apcu_cache_miss_signs_inside_generator_passed_to_apcu_entry(): void
    {
        $creds = new Credentials('K', 's', 'sess', time() + 3600);
        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->once()->andReturn('signed-once');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);
        $provider->shouldReceive('apcuAvailable')->andReturn(true);

        $generatorRanInsideApcuEntry = false;
        $provider->shouldReceive('apcuEntry')
            ->once()
            ->andReturnUsing(function ($key, $gen) use (&$generatorRanInsideApcuEntry) {
                $generatorRanInsideApcuEntry = true;
                return $gen();
            });

        $token = $provider->getToken('host', 3306, 'user', 'region');

        $this->assertSame('signed-once', $token);
        $this->assertTrue($generatorRanInsideApcuEntry,
            'Sign generator must be invoked via apcuEntry so apcu_entry atomicity is preserved.');
    }

    public function test_credentials_resolved_once_per_get_token_miss(): void
    {
        $creds = new Credentials('K', 's', 'sess', time() + 3600);
        $callCount = 0;
        $credentialProvider = function () use (&$callCount, $creds) {
            $callCount++;
            return Create::promiseFor($creds);
        };

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->andReturn('signed-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('apcuAvailable')->andReturn(false);

        $passedToFactory = null;
        $provider->shouldReceive('createAuthTokenGenerator')
            ->andReturnUsing(function ($creds = null) use ($generator, &$passedToFactory) {
                $passedToFactory = $creds;
                return $generator;
            });

        $provider->getToken('host', 3306, 'user', 'region');

        $this->assertSame(1, $callCount,
            'Credential provider must be invoked exactly once per cache miss.');
        $this->assertInstanceOf(CredentialsInterface::class, $passedToFactory,
            'createAuthTokenGenerator must receive the already-resolved credentials so the signer cannot re-resolve.');
    }

    public function test_debug_log_reads_credentials_from_laravel_cache_when_apcu_unavailable(): void
    {
        config([
            'iam-auth.debug' => true,
            'iam-auth.cache_store' => 'file',
        ]);
        cache()->store('file')->flush();

        $creds = new Credentials('AKIAEXAMPLE12345', 'secret', 'sess', time() + 3600);
        cache()->store('file')->put(AwsCredentialCache::CACHE_KEY, $creds, 3600);

        $existingEntry = [
            'token' => 'cached-token',
            'sig_kid' => substr(hash('sha256', 'AKIAEXAMPLE12345sess'), 0, 16),
            'signed_at' => time() - 30,
        ];
        cache()->store('file')->put('rds_iam:host:3306:user:region', $existingEntry, 600);

        $credentialProvider = fn () => Create::promiseFor($creds);

        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')->andReturn('any-token');

        $provider = Mockery::mock(RdsTokenProvider::class, [$credentialProvider])
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('createAuthTokenGenerator')->andReturn($generator);

        Log::spy();

        $provider->getToken('host', 3306, 'user', 'region');

        Log::shouldHaveReceived('debug')
            ->withArgs(function (string $msg, array $ctx) {
                return $msg === 'iam-auth.token-access'
                    && $ctx['cred_present'] === true
                    && $ctx['cred_access_key_prefix'] === 'AKIAEXAM'
                    && $ctx['token_cache_hit'] === true
                    && $ctx['sig_kid_match'] === true;
            });
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
