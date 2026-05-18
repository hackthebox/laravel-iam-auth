<?php

namespace Hackthebox\IamAuth\Cache;

use Aws\CacheInterface;
use Hackthebox\IamAuth\ValidatesCacheStore;

class AwsCredentialCacheStore implements CacheInterface
{
    use ValidatesCacheStore;

    public function get($key)
    {
        return null;
    }

    public function set($key, $value, $ttl = 0): void
    {
    }

    public function remove($key): void
    {
    }
}
