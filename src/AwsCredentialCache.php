<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialsInterface;
use Illuminate\Support\Facades\Log;
use RuntimeException;

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

    public function credentialSnapshot(): array
    {
        $creds = $this->peek();
        $expiration = $creds?->getExpiration();
        $accessKey = $creds?->getAccessKeyId();

        return [
            'cred_present' => $creds !== null,
            'cred_is_expired' => $creds?->isExpired(),
            'cred_expires_in_s' => $expiration !== null ? ((int) $expiration) - time() : null,
            'cred_access_key_prefix' => $accessKey !== null ? substr($accessKey, 0, 8) : null,
        ];
    }

    public function peek(): ?CredentialsInterface
    {
        if ($this->apcuAvailable()) {
            $cached = $this->apcuFetch(self::CACHE_KEY);

            return $cached instanceof CredentialsInterface ? $cached : null;
        }

        $store = config('iam-auth.cache_store');
        if (! $store) {
            return null;
        }

        try {
            $this->assertSafeCacheStore($store);
            $cached = $this->resolveCacheStore($store)->get(self::CACHE_KEY);
        } catch (\Throwable) {
            return null;
        }

        return $cached instanceof CredentialsInterface ? $cached : null;
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
            $this->logExpiredOnArrival($credentials);

            throw new RuntimeException(
                'iam-auth: credential provider returned already-expired credentials'
            );
        }

        return $credentials;
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

    private function computeTtl(CredentialsInterface $credentials): int
    {
        $expiration = $credentials->getExpiration();

        if ($expiration === null) {
            return 0;
        }

        return max(0, $expiration - time() - $this->credentialsExpiryBuffer());
    }

    private function credentialsExpiryBuffer(): int
    {
        $value = config('iam-auth.credentials_expiry_buffer', self::DEFAULT_CREDENTIALS_EXPIRY_BUFFER);

        return self::isValidCredentialsExpiryBufferValue($value)
            ? (int) $value
            : self::DEFAULT_CREDENTIALS_EXPIRY_BUFFER;
    }

    public static function isValidCredentialsExpiryBufferValue(mixed $value): bool
    {
        return is_numeric($value) && (int) $value >= 0;
    }

}
