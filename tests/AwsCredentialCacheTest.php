<?php

namespace Hackthebox\IamAuth\Tests;

use Aws\Credentials\Credentials;
use Hackthebox\IamAuth\AwsCredentialCache;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Mockery;
use Orchestra\Testbench\TestCase;

class AwsCredentialCacheTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IamAuthServiceProvider::class];
    }

    /**
     * Create an AwsCredentialCache with APCu disabled, so tests exercise
     * the Laravel cache path regardless of the test environment.
     */
    private function cacheWithoutApcu(): AwsCredentialCache
    {
        $cache = Mockery::mock(AwsCredentialCache::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $cache->shouldReceive('apcuAvailable')->andReturn(false);

        return $cache;
    }

    /**
     * Create an AwsCredentialCache with APCu enabled and the cache miss/hit
     * primitives mocked. APCu is rarely available in CLI; this lets us
     * exercise the APCu branch deterministically without the extension.
     *
     * @param  mixed  $fetched  the value apcuFetch returns (null = miss)
     */
    private function cacheWithApcu(mixed $fetched = null): AwsCredentialCache
    {
        $cache = Mockery::mock(AwsCredentialCache::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $cache->shouldReceive('apcuAvailable')->andReturn(true);
        $cache->shouldReceive('apcuFetch')->andReturn($fetched);

        return $cache;
    }

    public function test_caches_credentials_in_laravel_cache_store(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $callCount = 0;
        $provider = function () use (&$callCount) {
            $callCount++;
            return new Credentials('access-key', 'secret-key', 'token', time() + 3600);
        };

        $cache = $this->cacheWithoutApcu();

        $creds1 = $cache->resolve($provider);
        $creds2 = $cache->resolve($provider);

        $this->assertSame('access-key', $creds1->getAccessKeyId());
        $this->assertSame('access-key', $creds2->getAccessKeyId());
        $this->assertSame(1, $callCount, 'Provider should only be called once');
    }

    public function test_skips_caching_when_disabled(): void
    {
        config(['iam-auth.cache_store' => null]);

        $callCount = 0;
        $provider = function () use (&$callCount) {
            $callCount++;
            return new Credentials('access-key', 'secret-key', 'token', time() + 3600);
        };

        $cache = $this->cacheWithoutApcu();

        $cache->resolve($provider);
        $cache->resolve($provider);

        $this->assertSame(2, $callCount, 'Provider should be called each time when caching disabled');
    }

    public function test_throws_on_database_cache_store(): void
    {
        config([
            'iam-auth.cache_store' => 'db_cache',
            'cache.stores.db_cache' => ['driver' => 'database', 'table' => 'cache'],
        ]);

        $cache = $this->cacheWithoutApcu();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("cannot use the 'db_cache' cache store");

        $cache->resolve(fn () => new Credentials('a', 'b'));
    }

    public function test_resolves_valid_cache_store(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $cache = $this->cacheWithoutApcu();

        $creds = $cache->resolve(fn () => new Credentials('key', 'secret', 'token', time() + 3600));

        $this->assertSame('key', $creds->getAccessKeyId());
    }

    public function test_throws_on_nonexistent_cache_store(): void
    {
        config(['iam-auth.cache_store' => 'nonexistent']);

        $cache = $this->cacheWithoutApcu();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("IAM auth cache store 'nonexistent' is not configured");

        $cache->resolve(fn () => new Credentials('a', 'b'));
    }

    public function test_laravel_cache_throws_on_expired_on_arrival_credentials(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $provider = fn () => new Credentials('access-key', 'secret-key', 'token', time() - 1);

        $cache = $this->cacheWithoutApcu();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('iam-auth: credential provider returned already-expired credentials');

        $cache->resolve($provider);
    }

    public function test_apcu_throws_on_expired_on_arrival_credentials(): void
    {
        $provider = fn () => new Credentials('access-key', 'secret-key', 'token', time() - 1);

        $cache = $this->cacheWithApcu(fetched: null);
        $cache->shouldNotReceive('apcuStore');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('iam-auth: credential provider returned already-expired credentials');

        $cache->resolve($provider);
    }

    public function test_apcu_returns_cached_credentials_when_present_and_fresh(): void
    {
        $cached = new Credentials('cached-key', 'cached-secret', 'cached-token', time() + 3600);

        $callCount = 0;
        $provider = function () use (&$callCount) {
            $callCount++;
            return new Credentials('fresh-key', 'fresh-secret', 'fresh-token', time() + 3600);
        };

        $cache = $this->cacheWithApcu(fetched: $cached);

        $result = $cache->resolve($provider);

        $this->assertSame('cached-key', $result->getAccessKeyId());
        $this->assertSame(0, $callCount, 'Provider must not be called on cache hit.');
    }

    public function test_apcu_refreshes_cached_credentials_when_expired(): void
    {
        $cached = new Credentials('stale-key', 'stale-secret', 'stale-token', time() - 1);

        $callCount = 0;
        $provider = function () use (&$callCount) {
            $callCount++;
            return new Credentials('fresh-key', 'fresh-secret', 'fresh-token', time() + 3600);
        };

        $cache = $this->cacheWithApcu(fetched: $cached);
        $cache->shouldReceive('apcuStore')->once();

        $result = $cache->resolve($provider);

        $this->assertSame('fresh-key', $result->getAccessKeyId());
        $this->assertSame(1, $callCount);
    }

    public function test_credentials_within_safety_buffer_are_not_persisted(): void
    {
        // Credentials that expire in 200s. Under the new 300s buffer this
        // computes a negative TTL (so write is skipped). Under a 60s buffer
        // the TTL would be 140s and the entry would be cached. The skip is
        // the desirable behavior: don't persist credentials that will
        // expire before a refresh round-trip can plausibly absorb the
        // boundary, especially under clock drift.
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $provider = fn () => new Credentials('access-key', 'secret-key', 'token', time() + 200);

        $cache = $this->cacheWithoutApcu();

        $cache->resolve($provider);

        $this->assertNull(
            cache()->store('file')->get('iam_auth:aws_credentials'),
            'Credentials within the 300s safety buffer must not be persisted.'
        );
    }

    public function test_apcu_credentials_within_safety_buffer_are_not_persisted(): void
    {
        $provider = fn () => new Credentials('access-key', 'secret-key', 'token', time() + 200);

        $cache = $this->cacheWithApcu(fetched: null);
        $cache->shouldNotReceive('apcuStore');

        $cache->resolve($provider);
    }

    public function test_laravel_cache_does_not_persist_expired_on_arrival_credentials(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $provider = fn () => new Credentials('access-key', 'secret-key', 'token', time() - 1);

        $cache = $this->cacheWithoutApcu();

        try {
            $cache->resolve($provider);
        } catch (\RuntimeException) {
            // expected
        }

        $this->assertNull(
            cache()->store('file')->get('iam_auth:aws_credentials'),
            'Expired credentials must not be written to the cache.'
        );
    }
}
