<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialsInterface;

class AwsCredentialCache
{
    use ValidatesCacheStore;

    public const CACHE_KEY = 'iam_auth:aws_credentials';

    public const DEFAULT_CREDENTIALS_EXPIRY_BUFFER = 10;

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
            // No expiration reported: cache for 1 hour. Reasonable default for
            // synthetic providers (mostly tests) that don't surface an expiry.
            return 3600;
        }

        return max(0, $expiration - time() - $this->credentialsExpiryBuffer());
    }

    private function credentialsExpiryBuffer(): int
    {
        $value = config('iam-auth.credentials_expiry_buffer', self::DEFAULT_CREDENTIALS_EXPIRY_BUFFER);

        if (! is_numeric($value) || (int) $value < 0) {
            return self::DEFAULT_CREDENTIALS_EXPIRY_BUFFER;
        }

        return (int) $value;
    }

}
