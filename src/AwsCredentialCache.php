<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialsInterface;
use RuntimeException;

class AwsCredentialCache
{
    private const UNSAFE_CACHE_DRIVERS = ['database', 'dynamodb'];

    private const CACHE_KEY = 'aws_credentials';

    /**
     * Resolve credentials, using APCu or Laravel cache when available.
     *
     * @param callable(): CredentialsInterface $provider
     */
    public function resolve(callable $provider): CredentialsInterface
    {
        $store = config('iam-auth.credential_cache');

        if (! $store && ! $this->apcuAvailable()) {
            return $provider();
        }

        if ($this->apcuAvailable()) {
            return $this->resolveViaApcu($provider);
        }

        $this->assertSafeCacheStore($store);

        return $this->resolveViaLaravelCache($provider, $store);
    }

    protected function apcuAvailable(): bool
    {
        return function_exists('apcu_fetch') && apcu_enabled();
    }

    private function resolveViaApcu(callable $provider): CredentialsInterface
    {
        $cached = apcu_fetch(self::CACHE_KEY, $success);

        if ($success && $cached instanceof CredentialsInterface && ! $cached->isExpired()) {
            return $cached;
        }

        $credentials = $provider();

        $ttl = $this->computeTtl($credentials);
        if ($ttl > 0) {
            apcu_store(self::CACHE_KEY, $credentials, $ttl);
        }

        return $credentials;
    }

    private function resolveViaLaravelCache(callable $provider, string $store): CredentialsInterface
    {
        $cached = cache()->store($store)->get(self::CACHE_KEY);

        if ($cached instanceof CredentialsInterface && ! $cached->isExpired()) {
            return $cached;
        }

        $credentials = $provider();

        $ttl = $this->computeTtl($credentials);
        if ($ttl > 0) {
            cache()->store($store)->put(self::CACHE_KEY, $credentials, $ttl);
        }

        return $credentials;
    }

    private function computeTtl(CredentialsInterface $credentials): int
    {
        $expiration = $credentials->getExpiration();

        if ($expiration === null) {
            // No expiration: cache for 1 hour (reasonable default for
            // credentials that don't report expiry)
            return 3600;
        }

        // Leave a 60-second buffer before actual expiration
        return max(0, $expiration - time() - 60);
    }

    private function assertSafeCacheStore(string $store): void
    {
        $driver = config("cache.stores.{$store}.driver");

        if (in_array($driver, self::UNSAFE_CACHE_DRIVERS, true)) {
            throw new RuntimeException(
                "IAM auth cannot use the '{$store}' cache store (driver: {$driver}). "
                .'This would create a circular dependency. '
                .'Use a non-database cache store (e.g. file, redis, memcached) or set '
                ."'credential_cache' to null in config/iam-auth.php."
            );
        }
    }
}
