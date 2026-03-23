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

    public function test_refreshes_expired_credentials(): void
    {
        config(['iam-auth.cache_store' => 'file']);
        cache()->store('file')->flush();

        $callCount = 0;
        $provider = function () use (&$callCount) {
            $callCount++;
            // Already expired
            return new Credentials('access-key', 'secret-key', 'token', time() - 1);
        };

        $cache = $this->cacheWithoutApcu();

        $cache->resolve($provider);
        $cache->resolve($provider);

        // Expired credentials should not be reused from cache
        $this->assertSame(2, $callCount);
    }
}
