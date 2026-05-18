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
