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

    public function test_registers_aws_credential_cache(): void
    {
        $this->assertInstanceOf(
            \Hackthebox\IamAuth\AwsCredentialCache::class,
            $this->app->make(\Hackthebox\IamAuth\AwsCredentialCache::class)
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

    public function test_extends_aws_sdk_singleton(): void
    {
        $sdk = $this->app->make('aws');

        $this->assertInstanceOf(\Aws\Sdk::class, $sdk);
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
}
