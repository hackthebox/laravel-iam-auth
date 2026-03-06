<?php

namespace Hackthebox\RdsIamAuth;

use Aws\Credentials\CredentialProvider;
use Aws\Rds\AuthTokenGenerator;

class RdsAuthTokenProvider
{
    public function getToken(string $host, int $port, string $username, string $region): string
    {
        $cacheKey = "rds_iam:{$host}:{$port}:{$username}:{$region}";
        $ttl = config('rds-iam-auth.cache_ttl', 600);

        if (function_exists('apcu_entry') && apcu_enabled()) {
            return apcu_entry($cacheKey, fn () => $this->generateToken($host, $port, $username, $region), $ttl);
        }

        return $this->generateToken($host, $port, $username, $region);
    }

    private function generateToken(string $host, int $port, string $username, string $region): string
    {
        $generator = $this->createTokenGenerator();

        return $generator->createToken("{$host}:{$port}", $region, $username);
    }

    protected function createTokenGenerator(): AuthTokenGenerator
    {
        return new AuthTokenGenerator(CredentialProvider::defaultProvider());
    }
}
