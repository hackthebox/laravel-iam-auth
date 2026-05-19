<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialsInterface;
use Aws\Rds\AuthTokenGenerator;
use Hackthebox\IamAuth\Cache\CachedCredentialProvider;
use Illuminate\Support\Facades\Log;
use RuntimeException;
use Throwable;

class RdsTokenProvider
{
    public function __construct(
        private readonly CachedCredentialProvider $credentialProvider,
    ) {
    }

    public function getToken(
        string $host,
        int $port,
        string $username,
        string $region,
        bool $forceFresh = false,
    ): string {
        if ($forceFresh) {
            $this->credentialProvider->invalidate();
        }

        $credentials = ($this->credentialProvider)()->wait();

        $this->logTokenAccess($host, $port, $username, $region, $credentials, $forceFresh);

        return $this->generateToken($credentials, $host, $port, $username, $region);
    }

    public function credentialSnapshot(): array
    {
        return $this->credentialProvider->credentialSnapshot();
    }

    private function generateToken(
        CredentialsInterface $credentials,
        string $host,
        int $port,
        string $username,
        string $region,
    ): string {
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
        return new AuthTokenGenerator($credentials);
    }

    private function logTokenAccess(
        string $host,
        int $port,
        string $username,
        string $region,
        CredentialsInterface $credentials,
        bool $forceFresh,
    ): void {
        if (!config('iam-auth.debug', false)) {
            return;
        }

        Log::debug('iam-auth.token-access', [
            'host' => $host,
            'port' => $port,
            'username' => $username,
            'region' => $region,
            'force_fresh' => $forceFresh,
            'access_key_prefix' => substr($credentials->getAccessKeyId(), 0, 8),
        ]);
    }
}
