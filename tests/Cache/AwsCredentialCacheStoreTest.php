<?php

namespace Hackthebox\IamAuth\Tests\Cache;

use Aws\CacheInterface;
use Hackthebox\IamAuth\Cache\AwsCredentialCacheStore;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Orchestra\Testbench\TestCase;

class AwsCredentialCacheStoreTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IamAuthServiceProvider::class];
    }

    public function test_implements_aws_cache_interface(): void
    {
        $store = new AwsCredentialCacheStore();
        $this->assertInstanceOf(CacheInterface::class, $store);
    }
}
