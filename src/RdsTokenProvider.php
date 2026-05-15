<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialsInterface;
use Aws\Rds\AuthTokenGenerator;
use Closure;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Throwable;

class RdsTokenProvider
{
    use ValidatesCacheStore;

    public function __construct(private readonly Closure $credentialProvider)
    {
    }

    public function getToken(string $host, int $port, string $username, string $region): string
    {
        $cacheKey = "rds_iam:$host:$port:$username:$region";
        $ttl = config('iam-auth.cache_ttl', 600);
        $sigKid = $this->currentSigKid();

        $this->logTokenAccess($cacheKey, $sigKid);

        $sign = fn (): array => [
            'token' => $this->generateToken($host, $port, $username, $region),
            'sig_kid' => $sigKid,
            'signed_at' => time(),
        ];

        if ($this->apcuAvailable()) {
            $entry = $this->apcuEntry($cacheKey, $sign, $ttl);
            if (! $this->entryMatches($entry, $sigKid)) {
                $entry = $sign();
                $this->apcuStore($cacheKey, $entry, $ttl);
            }

            return $entry['token'];
        }

        $store = config('iam-auth.cache_store');

        if ($store) {
            $this->assertSafeCacheStore($store);

            $cache = $this->resolveCacheStore($store);
            $entry = $cache->get($cacheKey);
            if (! $this->entryMatches($entry, $sigKid)) {
                $entry = $sign();
                $cache->put($cacheKey, $entry, $ttl);
            }

            return $entry['token'];
        }

        return $sign()['token'];
    }

    private function entryMatches(mixed $entry, string $sigKid): bool
    {
        return is_array($entry)
            && isset($entry['token'], $entry['sig_kid'])
            && $entry['sig_kid'] === $sigKid;
    }

    private function currentSigKid(): string
    {
        return $this->credentialFingerprint(($this->credentialProvider)()->wait());
    }

    private function credentialFingerprint(CredentialsInterface $credentials): string
    {
        $material = $credentials->getAccessKeyId().($credentials->getSecurityToken() ?? '');

        return substr(hash('sha256', $material), 0, 16);
    }

    private function generateToken(string $host, int $port, string $username, string $region): string
    {
        try {
            $generator = $this->createAuthTokenGenerator();

            return $generator->createToken("$host:$port", $region, $username);
        } catch (Throwable $e) {
            throw new RuntimeException(
                "Failed to generate RDS IAM auth token for $username@$host:$port in region $region: {$e->getMessage()}",
                0,
                $e,
            );
        }
    }

    protected function createAuthTokenGenerator(): AuthTokenGenerator
    {
        return new AuthTokenGenerator($this->credentialProvider);
    }

    protected function apcuAvailable(): bool
    {
        return function_exists('apcu_entry') && apcu_enabled();
    }

    protected function apcuEntry(string $key, callable $generator, int $ttl): mixed
    {
        return apcu_entry($key, $generator, $ttl);
    }

    protected function apcuStore(string $key, mixed $value, int $ttl): void
    {
        apcu_store($key, $value, $ttl);
    }

    /**
     * Emit a debug log line describing the current state of the credential
     * and token caches. Used during the 1045 rejection investigation to
     * correlate cached-credential health with rejection events.
     *
     * Gated on iam-auth.debug to keep the per-DB-connection volume off in
     * production by default. Never logs secrets; only an AccessKeyId prefix
     * and the truncated sig_kid (already a one-way hash).
     */
    private function logTokenAccess(string $cacheKey, string $currentSigKid): void
    {
        if (! config('iam-auth.debug', false)) {
            return;
        }

        $creds = null;
        $tokenEntry = null;

        if ($this->apcuAvailable()) {
            $cached = apcu_fetch(AwsCredentialCache::CACHE_KEY, $credFound);
            if ($credFound && $cached instanceof CredentialsInterface) {
                $creds = $cached;
            }
            $tokenEntry = apcu_fetch($cacheKey, $tokenFound);
            if (! $tokenFound) {
                $tokenEntry = null;
            }
        }

        Log::debug('iam-auth.token-access', [
            'cache_key' => $cacheKey,
            'current_sig_kid' => $currentSigKid,
            'token_cache_hit' => is_array($tokenEntry) && isset($tokenEntry['sig_kid']),
            'cached_sig_kid' => is_array($tokenEntry) ? ($tokenEntry['sig_kid'] ?? null) : null,
            'sig_kid_match' => is_array($tokenEntry)
                && isset($tokenEntry['sig_kid'])
                && $tokenEntry['sig_kid'] === $currentSigKid,
            'cred_present' => $creds !== null,
            'cred_is_expired' => $creds?->isExpired(),
            'cred_expires_in_s' => $creds && $creds->getExpiration()
                ? $creds->getExpiration() - time()
                : null,
            'cred_access_key_prefix' => $creds?->getAccessKeyId()
                ? substr($creds->getAccessKeyId(), 0, 8)
                : null,
        ]);
    }
}
