<?php

namespace Hackthebox\IamAuth\Tests;

use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Orchestra\Testbench\TestCase;

class IamAuthServiceProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            \Aws\Laravel\AwsServiceProvider::class,
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
        $this->assertSame(600, config('iam-auth.cache_ttl'));
        $this->assertStringEndsWith('resources/certs/global-bundle.pem', config('iam-auth.ssl_ca_path'));
    }

    public function test_registers_credential_provider_binding(): void
    {
        $provider = $this->app->make('iam-auth.credential-provider');

        $this->assertIsCallable($provider);
    }

    /**
     * @dataProvider validCredentialProviderNames
     */
    public function test_builds_all_supported_credential_providers(string $name): void
    {
        config(['iam-auth.credential_provider' => $name]);

        // Force re-resolution of the singleton
        $this->app->forgetInstance('iam-auth.credential-provider');

        $provider = $this->app->make('iam-auth.credential-provider');
        $this->assertIsCallable($provider);
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

        $this->app->forgetInstance('iam-auth.credential-provider');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Unsupported IAM auth credential provider 'banana'");

        $this->app->make('iam-auth.credential-provider');
    }

    public function test_binds_aws_cache_interface_to_credential_cache_store(): void
    {
        $store = app(\Aws\CacheInterface::class);
        $this->assertInstanceOf(\Hackthebox\IamAuth\Cache\AwsCredentialCacheStore::class, $store);
    }

    public function test_binds_cached_and_fresh_credential_providers_as_distinct_callables(): void
    {
        $cached = app('iam-auth.credential-provider');
        $fresh = app('iam-auth.credential-provider-fresh');

        $this->assertIsCallable($cached);
        $this->assertIsCallable($fresh);
        $this->assertNotSame($cached, $fresh);
    }

    public function test_rds_token_provider_resolves_with_two_providers(): void
    {
        $provider = app(\Hackthebox\IamAuth\RdsTokenProvider::class);
        $this->assertInstanceOf(\Hackthebox\IamAuth\RdsTokenProvider::class, $provider);
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
}
