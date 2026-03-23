<?php

namespace Hackthebox\IamAuth;

use Aws\Rds\AuthTokenGenerator;
use RuntimeException;

class RdsTokenProvider
{
    use ValidatesCacheStore;

    public function __construct(private readonly \Closure $credentialProvider)
    {
    }

    public function getToken(string $host, int $port, string $username, string $region): string
    {
        $cacheKey = "rds_iam:{$host}:{$port}:{$username}:{$region}";
        $ttl = config('iam-auth.cache_ttl', 600);
        $generator = fn () => $this->generateToken($host, $port, $username, $region);

        if (function_exists('apcu_entry') && apcu_enabled()) {
            return apcu_entry($cacheKey, $generator, $ttl);
        }

        $store = config('iam-auth.cache_store');

        if ($store) {
            $this->assertSafeCacheStore($store);

            return cache()->store($store)->remember($cacheKey, $ttl, $generator);
        }

        return $generator();
    }

    private function generateToken(string $host, int $port, string $username, string $region): string
    {
        try {
            $generator = $this->createAuthTokenGenerator();

            return $generator->createToken("{$host}:{$port}", $region, $username);
        } catch (\Throwable $e) {
            throw new RuntimeException(
                "Failed to generate RDS IAM auth token for {$username}@{$host}:{$port} in region {$region}: {$e->getMessage()}",
                0,
                $e,
            );
        }
    }

    protected function createAuthTokenGenerator(): AuthTokenGenerator
    {
        return new AuthTokenGenerator($this->credentialProvider);
    }
}
