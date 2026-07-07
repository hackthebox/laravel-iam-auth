<?php

namespace Hackthebox\IamAuth\Tests\Cache;

use Aws\CacheInterface;
use Aws\Credentials\Credentials;
use Aws\Credentials\CredentialsInterface;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Hackthebox\IamAuth\Cache\CachedCredentialProvider;
use Illuminate\Support\Facades\Log;
use Mockery;
use Orchestra\Testbench\TestCase;
use ReflectionProperty;
use RuntimeException;

class CachedCredentialProviderTest extends TestCase
{
    public function test_returns_cached_creds_when_in_process_state_is_fresh(): void
    {
        $creds = $this->fresh('AKIAHOT');
        $baseCalls = 0;
        $base = function () use (&$baseCalls, $creds) {
            $baseCalls++;
            return Create::promiseFor($creds);
        };

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $first = $provider()->wait();
        $second = $provider()->wait();

        $this->assertSame($creds, $first);
        $this->assertSame($creds, $second);
        $this->assertSame(1, $baseCalls, 'base must be invoked at most once when in-process memo is fresh');
    }

    public function test_reads_from_store_on_cold_worker(): void
    {
        $creds = $this->fresh('AKIASTORE');
        $base = function () {
            throw new RuntimeException('base must not be called when store has fresh creds');
        };

        $store = $this->createMock(CacheInterface::class);
        $store->expects($this->once())->method('get')->with('k')->willReturn($creds);

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $this->assertSame($creds, $provider()->wait());
    }

    public function test_foreign_object_from_store_is_treated_as_miss(): void
    {
        // Laravel 13 cache.serializable_classes => false yields a __PHP_Incomplete_Class on read; must re-fetch.
        $fresh = $this->fresh('AKIAFRESH');
        $baseCalls = 0;
        $base = function () use (&$baseCalls, $fresh) {
            $baseCalls++;
            return Create::promiseFor($fresh);
        };

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn((object) ['not' => 'a credential']);

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $this->assertSame($fresh, $provider()->wait());
        $this->assertSame(1, $baseCalls, 'a foreign object in the cache slot must not satisfy the read');
    }

    public function test_writes_to_store_after_fetching_from_base(): void
    {
        $creds = $this->fresh('AKIABASE', ttl: 600);
        $base = static fn () => Create::promiseFor($creds);

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);
        $store->expects($this->once())
            ->method('set')
            ->with('k', $this->identicalTo($creds), $this->greaterThan(0));

        $provider = new CachedCredentialProvider($base, $store, 'k');
        $provider()->wait();
    }

    public function test_refreshes_when_creds_are_within_refresh_window(): void
    {
        $almostExpired = new Credentials('AKIAOLD', 'secret', null, time() + 30);
        $fresh = $this->fresh('AKIANEW');

        $baseCalls = 0;
        $base = function () use (&$baseCalls, $fresh) {
            $baseCalls++;
            return Create::promiseFor($fresh);
        };

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn($almostExpired);

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $result = $provider()->wait();

        $this->assertSame($fresh, $result);
        $this->assertSame(1, $baseCalls);
    }

    public function test_invalidate_clears_in_process_state_and_store(): void
    {
        $creds = $this->fresh('AKIA');
        $base = static fn () => Create::promiseFor($creds);

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);
        $store->expects($this->once())->method('remove')->with('k');

        $provider = new CachedCredentialProvider($base, $store, 'k');
        $provider()->wait();
        $provider->invalidate();

        $this->assertNull($this->inProcess($provider));
    }

    public function test_invalidate_then_invoke_fetches_fresh_and_writes_to_store(): void
    {
        $creds1 = $this->fresh('AKIAONE');
        $creds2 = $this->fresh('AKIATWO');

        $baseCalls = 0;
        $base = function () use (&$baseCalls, $creds1, $creds2) {
            $baseCalls++;
            return Create::promiseFor($baseCalls === 1 ? $creds1 : $creds2);
        };

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);
        $store->expects($this->exactly(2))->method('set');
        $store->expects($this->once())->method('remove');

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $first = $provider()->wait();
        $provider->invalidate();
        $second = $provider()->wait();

        $this->assertSame($creds1, $first);
        $this->assertSame($creds2, $second);
        $this->assertSame(2, $baseCalls);
    }

    public function test_invalidate_then_invoke_bypasses_stale_store_when_remove_silently_failed(): void
    {
        $stale = $this->fresh('AKIASTALE');
        $fresh = $this->fresh('AKIANEW');

        $baseCalls = 0;
        $base = function () use (&$baseCalls, $fresh) {
            $baseCalls++;
            return Create::promiseFor($fresh);
        };

        $store = $this->createMock(CacheInterface::class);
        $store->expects($this->never())->method('get');
        $store->method('remove');

        $provider = new CachedCredentialProvider($base, $store, 'k');
        $provider->invalidate();

        $result = $provider()->wait();

        $this->assertSame($fresh, $result);
        $this->assertSame(1, $baseCalls);
        $this->assertNotSame($stale, $result);
    }

    public function test_bypass_flag_is_consumed_after_one_invocation(): void
    {
        $cached = $this->fresh('AKIACACHED');
        $freshA = $this->fresh('AKIAFRESHA');
        $freshB = $this->fresh('AKIAFRESHB');

        $baseCalls = 0;
        $base = function () use (&$baseCalls, $freshA, $freshB) {
            $baseCalls++;
            return Create::promiseFor($baseCalls === 1 ? $freshA : $freshB);
        };

        $getCalls = 0;
        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturnCallback(function () use (&$getCalls, $cached) {
            $getCalls++;
            return $cached;
        });
        $store->method('remove');

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $provider->invalidate();
        $first = $provider()->wait();
        $this->assertSame($freshA, $first);
        $this->assertSame(0, $getCalls, 'invalidate() must skip store on the next invoke');

        $this->clearInProcess($provider);
        $second = $provider()->wait();
        $this->assertSame($cached, $second, 'after bypass is consumed, store is read again');
        $this->assertSame(1, $getCalls);
        $this->assertSame(1, $baseCalls, 'cached entry from store must satisfy second invoke without calling base');
    }

    public function test_accepts_invokable_class_base(): void
    {
        $creds = $this->fresh('AKIAINVK');
        $base = new class($creds) {
            public function __construct(private readonly CredentialsInterface $creds)
            {
            }

            public function __invoke(): PromiseInterface
            {
                return Create::promiseFor($this->creds);
            }
        };

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);

        $provider = new CachedCredentialProvider(static fn () => $base(), $store, 'k');

        $this->assertSame($creds, $provider()->wait());
    }

    public function test_credential_snapshot_when_empty(): void
    {
        $base = static fn () => Create::promiseFor(new Credentials('AKIA', 's', null, time() + 3600));
        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $snapshot = $provider->credentialSnapshot();

        $this->assertFalse($snapshot['cred_present']);
        $this->assertNull($snapshot['cred_access_key_prefix']);
    }

    public function test_credential_snapshot_after_fetch(): void
    {
        $creds = new Credentials('AKIASNAP12345', 'secret', null, time() + 1200);
        $base = static fn () => Create::promiseFor($creds);
        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);

        $provider = new CachedCredentialProvider($base, $store, 'k');
        $provider()->wait();

        $snapshot = $provider->credentialSnapshot();

        $this->assertTrue($snapshot['cred_present']);
        $this->assertSame('AKIASNAP', $snapshot['cred_access_key_prefix']);
        $this->assertFalse($snapshot['cred_is_expired']);
        $this->assertEqualsWithDelta(1200, $snapshot['cred_expires_in_s'], 2);
    }

    public function test_does_not_write_to_store_when_credentials_have_no_expiration(): void
    {
        $store = $this->createMock(CacheInterface::class);
        $store->expects($this->never())->method('set');
        $store->method('get')->willReturn(null);

        $staticCreds = new Credentials('AKIASTATIC', 'secret');
        $base = fn () => Create::promiseFor($staticCreds);

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $result = $provider()->wait();

        $this->assertSame('AKIASTATIC', $result->getAccessKeyId());
    }

    public function test_throws_and_logs_when_base_returns_already_expired_credentials(): void
    {
        Log::spy();

        $store = $this->createMock(CacheInterface::class);
        $store->expects($this->never())->method('set');
        $store->method('get')->willReturn(null);

        $expired = new Credentials('AKIAEXPIRED', 'secret', null, time() - 60);
        $base = fn () => Create::promiseFor($expired);

        $provider = new CachedCredentialProvider($base, $store, 'k');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('iam-auth: credential provider returned already-expired credentials');

        try {
            $provider()->wait();
        } finally {
            Log::shouldHaveReceived('warning')
                ->with('iam-auth.credentials-expired-on-arrival', Mockery::on(function ($payload) {
                    return $payload['cred_access_key_prefix'] === 'AKIAEXPI'
                        && $payload['expired_for_s'] >= 1;
                }))
                ->once();
        }
    }

    private function fresh(string $accessKey, int $ttl = 3600): CredentialsInterface
    {
        return new Credentials($accessKey, 'secret', null, time() + $ttl);
    }

    private function inProcess(CachedCredentialProvider $provider): ?CredentialsInterface
    {
        $ref = new ReflectionProperty($provider, 'inProcess');
        return $ref->getValue($provider);
    }

    private function clearInProcess(CachedCredentialProvider $provider): void
    {
        $ref = new ReflectionProperty($provider, 'inProcess');
        $ref->setValue($provider, null);
    }
}
