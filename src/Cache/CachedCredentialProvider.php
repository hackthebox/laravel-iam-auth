<?php

namespace Hackthebox\IamAuth\Cache;

use Aws\CacheInterface;
use Aws\Credentials\CredentialsInterface;
use Closure;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;

final class CachedCredentialProvider
{
    public const REFRESH_WINDOW = 60;

    private ?CredentialsInterface $inProcess = null;

    public function __construct(
        private readonly Closure $base,
        private readonly CacheInterface $store,
        private readonly string $cacheKey,
    ) {
    }

    public function __invoke(): PromiseInterface
    {
        if ($this->inProcess !== null && !$this->needsRefresh($this->inProcess)) {
            return Create::promiseFor($this->inProcess);
        }

        $cached = $this->store->get($this->cacheKey);
        if ($cached instanceof CredentialsInterface && !$this->needsRefresh($cached)) {
            $this->inProcess = $cached;
            return Create::promiseFor($cached);
        }

        return ($this->base)()->then(function (CredentialsInterface $creds) {
            $expiration = $creds->getExpiration();
            if ($expiration !== null) {
                $ttl = $expiration - time();
                if ($ttl > 0) {
                    $this->store->set($this->cacheKey, $creds, $ttl);
                }
            }
            $this->inProcess = $creds;
            return $creds;
        });
    }

    public function invalidate(): void
    {
        $this->inProcess = null;
        $this->store->remove($this->cacheKey);
    }

    public function credentialSnapshot(): array
    {
        $creds = $this->inProcess;

        if ($creds === null && $this->store instanceof AwsCredentialCacheStore) {
            $creds = $this->store->peek($this->cacheKey);
        }

        $expiration = $creds?->getExpiration();
        $accessKey = $creds?->getAccessKeyId();

        return [
            'cred_present' => $creds !== null,
            'cred_is_expired' => $creds?->isExpired(),
            'cred_expires_in_s' => $expiration !== null ? ((int) $expiration) - time() : null,
            'cred_access_key_prefix' => $accessKey !== null ? substr($accessKey, 0, 8) : null,
        ];
    }

    private function needsRefresh(CredentialsInterface $creds): bool
    {
        if ($creds->isExpired()) {
            return true;
        }
        $expiration = $creds->getExpiration();
        return $expiration !== null && $expiration - time() <= self::REFRESH_WINDOW;
    }
}
