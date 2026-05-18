<?php

namespace Hackthebox\IamAuth\Cache;

use Aws\CacheInterface;
use Aws\Credentials\CredentialsInterface;
use Hackthebox\IamAuth\ValidatesCacheStore;
use Illuminate\Support\Facades\Log;

class AwsCredentialCacheStore implements CacheInterface
{
    use ValidatesCacheStore;

    public const CACHE_KEY = 'aws_cached_iam_auth_credentials';

    public function get($key)
    {
        if ($this->apcuAvailable()) {
            $value = $this->apcuFetch($key);
            return $value === false ? null : $value;
        }

        $store = $this->cacheStoreName();
        if (!$store) {
            return null;
        }

        $this->assertSafeCacheStore($store);

        try {
            return $this->resolveCacheStore($store)->get($key);
        } catch (\Throwable) {
            return null;
        }
    }

    public function set($key, $value, $ttl = 0): void
    {
        if ($value instanceof CredentialsInterface && $value->isExpired()) {
            $this->logExpiredOnArrival($value);
            throw new \RuntimeException(
                'iam-auth: credential provider returned already-expired credentials'
            );
        }

        if ($this->apcuAvailable()) {
            $this->apcuStore($key, $value, $ttl);
            return;
        }

        $store = $this->cacheStoreName();
        if (!$store) {
            return;
        }

        $this->assertSafeCacheStore($store);
        $this->resolveCacheStore($store)->put($key, $value, $ttl);
    }

    private function logExpiredOnArrival(CredentialsInterface $credentials): void
    {
        $expiration = $credentials->getExpiration();
        $accessKey = $credentials->getAccessKeyId();

        Log::warning('iam-auth.credentials-expired-on-arrival', [
            'cred_access_key_prefix' => $accessKey ? substr($accessKey, 0, 8) : null,
            'expired_for_s' => $expiration !== null ? time() - ((int) $expiration) : null,
        ]);
    }

    public function remove($key): void
    {
        if ($this->apcuAvailable()) {
            $this->apcuDelete($key);
            return;
        }

        $store = $this->cacheStoreName();
        if (!$store) {
            return;
        }

        $this->assertSafeCacheStore($store);

        try {
            $this->resolveCacheStore($store)->forget($key);
        } catch (\Throwable) {
            // Best-effort cleanup. Sibling workers will retry on their own auth rejections.
        }
    }

    public function peek(string $key): ?CredentialsInterface
    {
        if ($this->apcuAvailable()) {
            $value = $this->apcuFetch($key);
            return $value instanceof CredentialsInterface ? $value : null;
        }

        $store = $this->cacheStoreName();
        if (!$store) {
            return null;
        }

        $value = $this->readStoreOrNullOnAnyFailure($store, $key);
        return $value instanceof CredentialsInterface ? $value : null;
    }

    private function readStoreOrNullOnAnyFailure(string $store, string $key): mixed
    {
        try {
            $this->assertSafeCacheStore($store);
            return $this->resolveCacheStore($store)->get($key);
        } catch (\Throwable) {
            return null;
        }
    }

    public function credentialSnapshot(): array
    {
        $creds = $this->peek(self::CACHE_KEY);
        $expiration = $creds?->getExpiration();
        $accessKey = $creds?->getAccessKeyId();

        return [
            'cred_present' => $creds !== null,
            'cred_is_expired' => $creds?->isExpired(),
            'cred_expires_in_s' => $expiration !== null ? ((int) $expiration) - time() : null,
            'cred_access_key_prefix' => $accessKey !== null ? substr($accessKey, 0, 8) : null,
        ];
    }

    protected function apcuAvailable(): bool
    {
        return function_exists('apcu_fetch') && apcu_enabled();
    }

    protected function apcuFetch(string $key): mixed
    {
        return apcu_fetch($key);
    }

    protected function apcuStore(string $key, mixed $value, int $ttl): bool
    {
        return apcu_store($key, $value, $ttl);
    }

    protected function apcuDelete(string $key): bool
    {
        return apcu_delete($key);
    }

    protected function cacheStoreName(): ?string
    {
        return config('iam-auth.cache_store');
    }
}
