<?php

namespace Hackthebox\IamAuth\Tests\Cache;

use Aws\CacheInterface;
use Hackthebox\IamAuth\Cache\AwsCredentialCacheStore;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Orchestra\Testbench\TestCase;

class AwsCredentialCacheStoreTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IamAuthServiceProvider::class];
    }

    public function test_implements_aws_cache_interface(): void
    {
        $store = new AwsCredentialCacheStore();
        $this->assertInstanceOf(CacheInterface::class, $store);
    }

    public function test_set_then_get_round_trips_credentials_via_apcu(): void
    {
        $store = $this->makeStore(apcuAvailable: true);
        $creds = new \Aws\Credentials\Credentials('AKIATEST', 'secret', null, time() + 3600);

        $store->set('test_key', $creds, 3600);
        $result = $store->get('test_key');

        $this->assertInstanceOf(\Aws\Credentials\CredentialsInterface::class, $result);
        $this->assertSame('AKIATEST', $result->getAccessKeyId());
    }

    public function test_remove_deletes_stored_value(): void
    {
        $store = $this->makeStore(apcuAvailable: true);
        $creds = new \Aws\Credentials\Credentials('AKIATEST', 'secret', null, time() + 3600);
        $store->set('test_key', $creds, 3600);

        $store->remove('test_key');

        $this->assertNull($store->get('test_key'));
    }

    public function test_falls_back_to_laravel_cache_when_apcu_unavailable(): void
    {
        $repo = $this->createMock(\Illuminate\Contracts\Cache\Repository::class);
        $creds = new \Aws\Credentials\Credentials('AKIAFALLBACK', 'secret', null, time() + 3600);

        $repo->expects($this->once())->method('put')->with('test_key', $this->isInstanceOf(\Aws\Credentials\CredentialsInterface::class), 3600);
        $repo->expects($this->once())->method('get')->with('test_key')->willReturn($creds);

        $factory = $this->createMock(\Illuminate\Contracts\Cache\Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $store->set('test_key', $creds, 3600);
        $result = $store->get('test_key');

        $this->assertSame('AKIAFALLBACK', $result->getAccessKeyId());
    }

    public function test_remove_via_laravel_cache_when_apcu_unavailable(): void
    {
        $repo = $this->createMock(\Illuminate\Contracts\Cache\Repository::class);
        $repo->expects($this->once())->method('forget')->with('test_key');

        $factory = $this->createMock(\Illuminate\Contracts\Cache\Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $store->remove('test_key');
    }

    public function test_get_returns_null_when_apcu_unavailable_and_no_cache_store_configured(): void
    {
        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: null, factory: null);

        $this->assertNull($store->get('test_key'));
    }

    public function test_remove_swallows_throwable_from_laravel_cache(): void
    {
        $repo = $this->createMock(\Illuminate\Contracts\Cache\Repository::class);
        $repo->method('forget')->willThrowException(new \RuntimeException('redis down'));

        $factory = $this->createMock(\Illuminate\Contracts\Cache\Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $store->remove('test_key');
        $this->addToAssertionCount(1);
    }

    public function test_set_propagates_throwable_from_laravel_cache(): void
    {
        $repo = $this->createMock(\Illuminate\Contracts\Cache\Repository::class);
        $repo->method('put')->willThrowException(new \RuntimeException('redis down'));

        $factory = $this->createMock(\Illuminate\Contracts\Cache\Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);
        $creds = new \Aws\Credentials\Credentials('AKIATEST', 'secret', null, time() + 3600);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('redis down');

        $store->set('test_key', $creds, 3600);
    }

    public function test_set_with_expired_credentials_logs_warning_and_throws(): void
    {
        \Illuminate\Support\Facades\Log::spy();

        $store = $this->makeStore(apcuAvailable: true);
        $expired = new \Aws\Credentials\Credentials('AKIAEXPIRED', 'secret', null, time() - 60);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('iam-auth: credential provider returned already-expired credentials');

        try {
            $store->set('test_key', $expired, 3600);
        } finally {
            \Illuminate\Support\Facades\Log::shouldHaveReceived('warning')
                ->with('iam-auth.credentials-expired-on-arrival', \Mockery::on(function ($payload) {
                    return $payload['cred_access_key_prefix'] === 'AKIAEXPI'
                        && $payload['expired_for_s'] >= 1;
                }))
                ->once();
        }
    }

    private function makeStoreWithFactory(bool $apcuAvailable, ?string $cacheStore, ?\Illuminate\Contracts\Cache\Factory $factory): AwsCredentialCacheStore
    {
        return new class($apcuAvailable, $cacheStore, $factory) extends AwsCredentialCacheStore {
            public function __construct(private bool $apcuOn, private ?string $store, private ?\Illuminate\Contracts\Cache\Factory $factory)
            {
            }

            protected function apcuAvailable(): bool
            {
                return $this->apcuOn;
            }

            protected function cacheStoreName(): ?string
            {
                return $this->store;
            }

            protected function resolveCacheStore(string $name): \Illuminate\Contracts\Cache\Repository
            {
                return $this->factory->store($name);
            }
        };
    }

    private function makeStore(bool $apcuAvailable, ?string $cacheStore = null): AwsCredentialCacheStore
    {
        return new class($apcuAvailable, $cacheStore) extends AwsCredentialCacheStore {
            private array $apcu = [];

            public function __construct(private bool $apcuOn, private ?string $store)
            {
            }

            protected function apcuAvailable(): bool
            {
                return $this->apcuOn;
            }

            protected function apcuFetch(string $key): mixed
            {
                return $this->apcu[$key] ?? false;
            }

            protected function apcuStore(string $key, mixed $value, int $ttl): bool
            {
                $this->apcu[$key] = $value;
                return true;
            }

            protected function apcuDelete(string $key): bool
            {
                unset($this->apcu[$key]);
                return true;
            }

            protected function cacheStoreName(): ?string
            {
                return $this->store;
            }
        };
    }
}
