<?php

namespace Hackthebox\IamAuth\Cache;

use Aws\CacheInterface;
use Hackthebox\IamAuth\ValidatesCacheStore;

class AwsCredentialCacheStore implements CacheInterface
{
    use ValidatesCacheStore;

    public function get($key)
    {
        if ($this->apcuAvailable()) {
            $value = $this->apcuFetch($key);
            return $value === false ? null : $value;
        }

        return null;
    }

    public function set($key, $value, $ttl = 0): void
    {
        if ($this->apcuAvailable()) {
            $this->apcuStore($key, $value, $ttl);
            return;
        }
    }

    public function remove($key): void
    {
        if ($this->apcuAvailable()) {
            $this->apcuDelete($key);
            return;
        }
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
