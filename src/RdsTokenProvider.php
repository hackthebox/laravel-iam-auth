<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialsInterface;
use Aws\Rds\AuthTokenGenerator;
use Closure;
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
        $cacheKey = $this->cacheKey($host, $port, $username, $region);
        $ttl = config('iam-auth.cache_ttl', 600);
        $generator = fn () => $this->generateToken($host, $port, $username, $region);

        if ($this->apcuAvailable()) {
            return $this->apcuEntry($cacheKey, $generator, $ttl);
        }

        $store = config('iam-auth.cache_store');

        if ($store) {
            $this->assertSafeCacheStore($store);

            return $this->resolveCacheStore($store)->remember($cacheKey, $ttl, $generator);
        }

        return $generator();
    }

    /**
     * Fingerprint-suffixed so a cached pre-signed URL is orphaned the
     * instant its signing credentials rotate, preventing reuse with a
     * potentially server-side-dead STS session.
     */
    private function cacheKey(string $host, int $port, string $username, string $region): string
    {
        $fingerprint = $this->credentialFingerprint($this->resolveCurrentCredentials());

        return "rds_iam:$host:$port:$username:$region:$fingerprint";
    }

    private function resolveCurrentCredentials(): CredentialsInterface
    {
        return ($this->credentialProvider)()->wait();
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

    protected function apcuEntry(string $key, callable $generator, int $ttl): string
    {
        return apcu_entry($key, $generator, $ttl);
    }
}
