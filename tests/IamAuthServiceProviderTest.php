<?php

namespace Hackthebox\IamAuth\Tests;

use Aws\CacheInterface;
use Aws\Laravel\AwsServiceProvider;
use GuzzleHttp\Promise\PromiseInterface;
use Hackthebox\IamAuth\Cache\AwsCredentialCacheStore;
use Hackthebox\IamAuth\Cache\CachedCredentialProvider;
use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;

class IamAuthServiceProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            AwsServiceProvider::class,
            IamAuthServiceProvider::class,
        ];
    }

    public function test_registers_mysql_connector(): void
    {
        $this->assertInstanceOf(
            IamMySqlConnector::class,
            $this->app->make('db.connector.mysql')
        );
    }

    public function test_registers_mariadb_connector(): void
    {
        $this->assertInstanceOf(
            IamMariaDbConnector::class,
            $this->app->make('db.connector.mariadb')
        );
    }

    public function test_registers_pgsql_connector(): void
    {
        $this->assertInstanceOf(
            IamPostgresConnector::class,
            $this->app->make('db.connector.pgsql')
        );
    }

    public function test_merges_config(): void
    {
        $this->assertNotNull(config('iam-auth.region'));
        $this->assertStringEndsWith('resources/certs/global-bundle.pem', config('iam-auth.ssl_ca_path'));
    }

    public function test_cached_credential_provider_is_singleton(): void
    {
        $a = app(CachedCredentialProvider::class);
        $b = app(CachedCredentialProvider::class);

        $this->assertSame($a, $b);
    }

    #[DataProvider('validCredentialProviderNames')]
    public function test_builds_all_supported_credential_providers(string $name): void
    {
        config(['iam-auth.credential_provider' => $name]);

        $this->app->forgetInstance(CachedCredentialProvider::class);

        $provider = $this->app->make(CachedCredentialProvider::class);
        $this->assertInstanceOf(CachedCredentialProvider::class, $provider);
    }

    public static function validCredentialProviderNames(): array
    {
        return [
            'default' => ['default'],
            'environment' => ['environment'],
            'ecs' => ['ecs'],
            'web_identity' => ['web_identity'],
            'instance_profile' => ['instance_profile'],
            'sso' => ['sso'],
            'ini' => ['ini'],
        ];
    }

    public function test_throws_on_unsupported_credential_provider(): void
    {
        config(['iam-auth.credential_provider' => 'banana']);

        $this->app->forgetInstance(CachedCredentialProvider::class);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage("Unsupported IAM auth credential provider 'banana'");

        $this->app->make(CachedCredentialProvider::class);
    }

    public function test_binds_aws_cache_interface_to_credential_cache_store(): void
    {
        $store = app(CacheInterface::class);
        $this->assertInstanceOf(AwsCredentialCacheStore::class, $store);
    }

    public function test_rds_token_provider_resolves_with_cached_provider(): void
    {
        $provider = app(RdsTokenProvider::class);
        $this->assertInstanceOf(RdsTokenProvider::class, $provider);
    }

    public function test_aws_credentials_config_injected_without_rebuilding_singleton(): void
    {
        $this->app->extend('aws', function ($sdk) {
            $sdk->__sentinel = 'preserved';
            return $sdk;
        });

        $sdk = app('aws');

        $this->assertTrue(property_exists($sdk, '__sentinel'));
        $this->assertSame('preserved', $sdk->__sentinel);
    }

    public function test_aws_credentials_config_uses_cached_credential_provider(): void
    {
        $resolved = config('aws.credentials');
        $this->assertIsCallable($resolved);

        $promise = $resolved();
        $this->assertInstanceOf(PromiseInterface::class, $promise);
    }

    public function test_ecs_credential_provider_does_not_crash_when_wrapped(): void
    {
        config(['iam-auth.credential_provider' => 'ecs']);
        $this->app->forgetInstance(CachedCredentialProvider::class);

        $provider = $this->app->make(CachedCredentialProvider::class);

        $this->assertInstanceOf(CachedCredentialProvider::class, $provider);
    }
}
