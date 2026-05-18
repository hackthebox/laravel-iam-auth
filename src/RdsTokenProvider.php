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

    public static function cacheKey(string $host, int $port, string $username, string $region): string
    {
        return "rds_iam:$host:$port:$username:$region";
    }

    public function getToken(string $host, int $port, string $username, string $region): string
    {
        $cacheKey = self::cacheKey($host, $port, $username, $region);
        $ttl = config('iam-auth.cache_ttl', 600);

        $credentials = ($this->credentialProvider)()->wait();
        $sigKid = $this->credentialFingerprint($credentials);

        $this->logTokenAccess($cacheKey, $sigKid);

        $sign = fn (): array => [
            'token' => $this->generateToken($credentials, $host, $port, $username, $region),
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

    private function credentialFingerprint(CredentialsInterface $credentials): string
    {
        $material = $credentials->getAccessKeyId().($credentials->getSecurityToken() ?? '');

        return substr(hash('sha256', $material), 0, 16);
    }

    private function generateToken(CredentialsInterface $credentials, string $host, int $port, string $username, string $region): string
    {
        try {
            $generator = $this->createAuthTokenGenerator($credentials);

            return $generator->createToken("$host:$port", $region, $username);
        } catch (Throwable $e) {
            throw new RuntimeException(
                "Failed to generate RDS IAM auth token for $username@$host:$port in region $region: {$e->getMessage()}",
                0,
                $e,
            );
        }
    }

    protected function createAuthTokenGenerator(CredentialsInterface $credentials): AuthTokenGenerator
    {
        return new AuthTokenGenerator(fn () => $credentials);
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

    private function logTokenAccess(string $cacheKey, string $currentSigKid): void
    {
        if (! config('iam-auth.debug', false)) {
            return;
        }

        $tokenEntry = $this->peekTokenEntry($cacheKey);

        Log::debug('iam-auth.token-access', [
            'cache_key' => $cacheKey,
            'current_sig_kid' => $currentSigKid,
            'token_cache_hit' => is_array($tokenEntry) && isset($tokenEntry['sig_kid']),
            'cached_sig_kid' => is_array($tokenEntry) ? ($tokenEntry['sig_kid'] ?? null) : null,
            'sig_kid_match' => is_array($tokenEntry)
                && isset($tokenEntry['sig_kid'])
                && $tokenEntry['sig_kid'] === $currentSigKid,
            ...app(AwsCredentialCache::class)->credentialSnapshot(),
        ]);
    }

    private function peekTokenEntry(string $cacheKey): ?array
    {
        if ($this->apcuAvailable()) {
            $entry = apcu_fetch($cacheKey, $found);

            return $found && is_array($entry) ? $entry : null;
        }

        $store = config('iam-auth.cache_store');
        if (! $store) {
            return null;
        }

        try {
            $this->assertSafeCacheStore($store);
            $entry = $this->resolveCacheStore($store)->get($cacheKey);
        } catch (Throwable) {
            return null;
        }

        return is_array($entry) ? $entry : null;
    }
}
