<?php

namespace Hackthebox\IamAuth;

use Illuminate\Contracts\Cache\Repository;
use RuntimeException;

trait ValidatesCacheStore
{
    private static array $unsafeCacheDrivers = ['database', 'dynamodb'];

    private function assertSafeCacheStore(string $store): void
    {
        $driver = config("cache.stores.$store.driver");

        if (in_array($driver, self::$unsafeCacheDrivers, true)) {
            throw new RuntimeException(
                "IAM auth cannot use the '$store' cache store (driver: $driver). "
                .'This would create a circular dependency. '
                .'Use a non-database cache store (e.g. file, redis, memcached) or set '
                ."'cache_store' to null in config/iam-auth.php."
            );
        }
    }

    private function resolveCacheStore(string $store): Repository
    {
        try {
            return cache()->store($store);
        } catch (\Throwable $e) {
            throw new RuntimeException(
                "IAM auth cache store '$store' is not configured. "
                ."Check the 'cache_store' value in config/iam-auth.php.",
                0,
                $e,
            );
        }
    }
}
