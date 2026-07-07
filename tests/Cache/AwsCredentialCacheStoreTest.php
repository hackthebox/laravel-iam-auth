<?php

namespace Hackthebox\IamAuth\Tests\Cache;

use Aws\CacheInterface;
use Aws\Credentials\Credentials;
use Aws\Credentials\CredentialsInterface;
use Hackthebox\IamAuth\Cache\AwsCredentialCacheStore;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Illuminate\Contracts\Cache\Factory;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Log;
use Mockery;
use Orchestra\Testbench\TestCase;
use RuntimeException;

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
        $creds = new Credentials('AKIATEST', 'secret', null, time() + 3600);

        $store->set('test_key', $creds, 3600);
        $result = $store->get('test_key');

        $this->assertInstanceOf(CredentialsInterface::class, $result);
        $this->assertSame('AKIATEST', $result->getAccessKeyId());
    }

    public function test_remove_deletes_stored_value(): void
    {
        $store = $this->makeStore(apcuAvailable: true);
        $creds = new Credentials('AKIATEST', 'secret', null, time() + 3600);
        $store->set('test_key', $creds, 3600);

        $store->remove('test_key');

        $this->assertNull($store->get('test_key'));
    }

    public function test_falls_back_to_laravel_cache_when_apcu_unavailable(): void
    {
        $repo = $this->createMock(Repository::class);
        $creds = new Credentials('AKIAFALLBACK', 'secret', null, time() + 3600);

        $repo->expects($this->once())->method('put')->with('test_key', $this->isInstanceOf(CredentialsInterface::class), 3600);
        $repo->expects($this->once())->method('get')->with('test_key')->willReturn($creds);

        $factory = $this->createMock(Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $store->set('test_key', $creds, 3600);
        $result = $store->get('test_key');

        $this->assertSame('AKIAFALLBACK', $result->getAccessKeyId());
    }

    public function test_remove_via_laravel_cache_when_apcu_unavailable(): void
    {
        $repo = $this->createMock(Repository::class);
        $repo->expects($this->once())->method('forget')->with('test_key');

        $factory = $this->createMock(Factory::class);
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
        $repo = $this->createMock(Repository::class);
        $repo->method('forget')->willThrowException(new RuntimeException('redis down'));

        $factory = $this->createMock(Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $store->remove('test_key');
        $this->addToAssertionCount(1);
    }

    public function test_set_swallows_throwable_from_laravel_cache_and_logs_warning(): void
    {
        Log::spy();

        $repo = $this->createMock(Repository::class);
        $repo->method('put')->willThrowException(new RuntimeException('redis down'));

        $factory = $this->createMock(Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);
        $creds = new Credentials('AKIATEST', 'secret', null, time() + 3600);

        $store->set('test_key', $creds, 3600);

        Log::shouldHaveReceived('warning')
            ->with('iam-auth.cache-store-write-failed', Mockery::on(function ($payload) {
                return $payload['store'] === 'redis'
                    && str_contains($payload['message'], 'redis down');
            }))
            ->once();

        $this->addToAssertionCount(1);
    }

    public function test_set_with_expired_credentials_logs_warning_and_throws(): void
    {
        Log::spy();

        $store = $this->makeStore(apcuAvailable: true);
        $expired = new Credentials('AKIAEXPIRED', 'secret', null, time() - 60);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('iam-auth: credential provider returned already-expired credentials');

        try {
            $store->set('test_key', $expired, 3600);
        } finally {
            Log::shouldHaveReceived('warning')
                ->with('iam-auth.credentials-expired-on-arrival', Mockery::on(function ($payload) {
                    return $payload['cred_access_key_prefix'] === 'AKIAEXPI'
                        && $payload['expired_for_s'] >= 1;
                }))
                ->once();
        }
    }

    public function test_peek_returns_stored_credentials_without_mutation(): void
    {
        $store = $this->makeStore(apcuAvailable: true);
        $creds = new Credentials('AKIAPEEK', 'secret', null, time() + 3600);
        $store->set('test_key', $creds, 3600);

        $peeked = $store->peek('test_key');

        $this->assertSame('AKIAPEEK', $peeked->getAccessKeyId());
        $this->assertSame('AKIAPEEK', $store->get('test_key')->getAccessKeyId());
    }

    public function test_credential_snapshot_returns_present_state(): void
    {
        $store = $this->makeStore(apcuAvailable: true);
        $creds = new Credentials('AKIASNAP12345', 'secret', null, time() + 1234);
        $store->set(AwsCredentialCacheStore::CACHE_KEY, $creds, 1234);

        $snapshot = $store->credentialSnapshot();

        $this->assertTrue($snapshot['cred_present']);
        $this->assertFalse($snapshot['cred_is_expired']);
        $this->assertEqualsWithDelta(1234, $snapshot['cred_expires_in_s'], 2);
        $this->assertSame('AKIASNAP', $snapshot['cred_access_key_prefix']);
    }

    public function test_credential_snapshot_when_empty(): void
    {
        $store = $this->makeStore(apcuAvailable: true);

        $snapshot = $store->credentialSnapshot();

        $this->assertFalse($snapshot['cred_present']);
        $this->assertNull($snapshot['cred_is_expired']);
        $this->assertNull($snapshot['cred_expires_in_s']);
        $this->assertNull($snapshot['cred_access_key_prefix']);
    }

    public function test_peek_returns_credentials_from_laravel_cache_when_apcu_unavailable(): void
    {
        $creds = new Credentials('AKIAPEEKL', 'secret', null, time() + 3600);

        $repo = $this->createMock(Repository::class);
        $repo->method('get')->with('test_key')->willReturn($creds);

        $factory = $this->createMock(Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $peeked = $store->peek('test_key');

        $this->assertInstanceOf(CredentialsInterface::class, $peeked);
        $this->assertSame('AKIAPEEKL', $peeked->getAccessKeyId());
    }

    public function test_peek_returns_null_when_laravel_cache_returns_foreign_object(): void
    {
        $repo = $this->createMock(Repository::class);
        $repo->method('get')->with('test_key')->willReturn((object) ['not' => 'a credential']);

        $factory = $this->createMock(Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $this->assertNull($store->peek('test_key'));
    }

    public function test_peek_returns_null_when_laravel_cache_throws(): void
    {
        $repo = $this->createMock(Repository::class);
        $repo->method('get')->willThrowException(new RuntimeException('redis down'));

        $factory = $this->createMock(Factory::class);
        $factory->method('store')->with('redis')->willReturn($repo);

        $store = $this->makeStoreWithFactory(apcuAvailable: false, cacheStore: 'redis', factory: $factory);

        $this->assertNull($store->peek('test_key'));
    }

    private function makeStoreWithFactory(bool $apcuAvailable, ?string $cacheStore, ?Factory $factory): AwsCredentialCacheStore
    {
        return new class($apcuAvailable, $cacheStore, $factory) extends AwsCredentialCacheStore {
            public function __construct(private readonly bool $apcuOn, private readonly ?string $store, private readonly ?Factory $factory)
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

            protected function resolveCacheStore(string $store): Repository
            {
                return $this->factory->store($store);
            }
        };
    }

    private function makeStore(bool $apcuAvailable, ?string $cacheStore = null): AwsCredentialCacheStore
    {
        return new class($apcuAvailable, $cacheStore) extends AwsCredentialCacheStore {
            private array $apcu = [];

            public function __construct(private readonly bool $apcuOn, private readonly ?string $store)
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
