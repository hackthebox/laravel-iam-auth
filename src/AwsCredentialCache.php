<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialsInterface;

class AwsCredentialCache
{
    use ValidatesCacheStore;

    private const CACHE_KEY = 'iam_auth:aws_credentials';

    /**
     * Resolve credentials, using APCu or Laravel cache when available.
     *
     * @param callable(): CredentialsInterface $provider
     */
    public function resolve(callable $provider): CredentialsInterface
    {
        $store = config('iam-auth.cache_store');

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
        $cached = $this->apcuFetch(self::CACHE_KEY);

        if ($cached instanceof CredentialsInterface && ! $cached->isExpired()) {
            return $cached;
        }

        $credentials = $this->resolveFreshCredentials($provider);

        $ttl = $this->computeTtl($credentials);
        if ($ttl > 0) {
            $this->apcuStore(self::CACHE_KEY, $credentials, $ttl);
        }

        return $credentials;
    }

    protected function apcuFetch(string $key): mixed
    {
        return apcu_fetch($key);
    }

    protected function apcuStore(string $key, mixed $value, int $ttl): void
    {
        apcu_store($key, $value, $ttl);
    }

    private function resolveViaLaravelCache(callable $provider, string $store): CredentialsInterface
    {
        $cache = $this->resolveCacheStore($store);
        $cached = $cache->get(self::CACHE_KEY);

        if ($cached instanceof CredentialsInterface && ! $cached->isExpired()) {
            return $cached;
        }

        $credentials = $this->resolveFreshCredentials($provider);

        $ttl = $this->computeTtl($credentials);
        if ($ttl > 0) {
            $cache->put(self::CACHE_KEY, $credentials, $ttl);
        }

        return $credentials;
    }

    /**
     * Refuses already-expired credentials so the SigV4 signer never emits
     * a token that RDS will reject server-side.
     */
    private function resolveFreshCredentials(callable $provider): CredentialsInterface
    {
        $credentials = $provider();

        if ($credentials->isExpired()) {
            throw new \RuntimeException(
                'iam-auth: credential provider returned already-expired credentials'
            );
        }

        return $credentials;
    }

    private function computeTtl(CredentialsInterface $credentials): int
    {
        $expiration = $credentials->getExpiration();

        if ($expiration === null) {
            return 3600;
        }

        // 300s buffer covers clock drift, SDK serving latency, and a
        // worker briefly holding the deserialized object past eviction.
        return max(0, $expiration - time() - 300);
    }

}
