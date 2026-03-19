<?php

namespace Hackthebox\RdsIamAuth;

use Aws\Credentials\CredentialProvider;
use Aws\Rds\AuthTokenGenerator;
use RuntimeException;

class RdsAuthTokenProvider
{
    private const UNSAFE_CACHE_DRIVERS = ['database', 'dynamodb'];

    public function getToken(string $host, int $port, string $username, string $region): string
    {
        $cacheKey = "rds_iam:{$host}:{$port}:{$username}:{$region}";
        $ttl = config('rds-iam-auth.cache_ttl', 600);
        $generator = fn () => $this->generateToken($host, $port, $username, $region);

        if (function_exists('apcu_entry') && apcu_enabled()) {
            return apcu_entry($cacheKey, $generator, $ttl);
        }

        $store = config('rds-iam-auth.cache_store');

        if ($store) {
            $this->assertSafeCacheStore($store);

            return cache()->store($store)->remember($cacheKey, $ttl, $generator);
        }

        return $generator();
    }

    private function assertSafeCacheStore(string $store): void
    {
        $driver = config("cache.stores.{$store}.driver");

        if (in_array($driver, self::UNSAFE_CACHE_DRIVERS, true)) {
            throw new RuntimeException(
                "RDS IAM auth cannot use the '{$store}' cache store (driver: {$driver}). "
                .'This would create a circular dependency — a database connection is needed '
                .'to cache the token that is needed to open the database connection. '
                .'Use a non-database cache store (e.g. file, redis, memcached) or set '
                ."'cache_store' to null in config/rds-iam-auth.php."
            );
        }
    }

    private function generateToken(string $host, int $port, string $username, string $region): string
    {
        try {
            $generator = $this->createTokenGenerator();

            return $generator->createToken("{$host}:{$port}", $region, $username);
        } catch (\Throwable $e) {
            throw new RuntimeException(
                "Failed to generate RDS IAM auth token for {$username}@{$host}:{$port} in region {$region}: {$e->getMessage()}",
                0,
                $e,
            );
        }
    }

    protected function createTokenGenerator(): AuthTokenGenerator
    {
        return new AuthTokenGenerator($this->resolveCredentialProvider());
    }

    private function resolveCredentialProvider(): callable
    {
        $provider = config('rds-iam-auth.credential_provider', 'default');

        return match ($provider) {
            'default' => CredentialProvider::defaultProvider(),
            'environment' => CredentialProvider::env(),
            'ecs' => CredentialProvider::ecsCredentials(),
            'web_identity' => CredentialProvider::assumeRoleWithWebIdentityCredentialProvider(),
            'instance_profile' => CredentialProvider::instanceProfile(),
            'sso' => CredentialProvider::sso(),
            'ini' => CredentialProvider::ini(),
            default => throw new RuntimeException(
                "Unsupported RDS IAM credential provider '{$provider}'. "
                ."Supported values: default, environment, ecs, web_identity, instance_profile, sso, ini."
            ),
        };
    }
}
