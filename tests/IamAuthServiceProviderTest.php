<?php

namespace Hackthebox\IamAuth\Tests;

use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Illuminate\Support\Facades\Log;
use Mockery;
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

    public function test_boot_warns_on_negative_credentials_expiry_buffer(): void
    {
        config(['iam-auth.credentials_expiry_buffer' => -100]);

        Log::spy();

        (new IamAuthServiceProvider($this->app))->boot();

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(function (string $message, array $context) {
                return str_contains($message, 'credentials_expiry_buffer')
                    && $context['value'] === -100;
            });
    }

    public function test_boot_does_not_warn_on_large_credentials_expiry_buffer(): void
    {
        // Large buffers are an operator choice (frequent refresh on short
        // sessions), not a misconfiguration. The runtime caches less, which
        // is observable as agent load; no boot-time warning.
        config(['iam-auth.credentials_expiry_buffer' => 3600]);

        Log::spy();

        (new IamAuthServiceProvider($this->app))->boot();

        Log::shouldNotHaveReceived('warning',
            [Mockery::pattern('/credentials_expiry_buffer/'), Mockery::any()]);
    }

    public function test_boot_warns_on_non_numeric_credentials_expiry_buffer(): void
    {
        config(['iam-auth.credentials_expiry_buffer' => 'not-a-number']);

        Log::spy();

        (new IamAuthServiceProvider($this->app))->boot();

        Log::shouldHaveReceived('warning')
            ->once()
            ->withArgs(fn (string $message) => str_contains($message, 'credentials_expiry_buffer'));
    }

    public function test_boot_does_not_warn_on_valid_credentials_expiry_buffer(): void
    {
        config(['iam-auth.credentials_expiry_buffer' => 10]);

        Log::spy();

        (new IamAuthServiceProvider($this->app))->boot();

        Log::shouldNotHaveReceived('warning',
            [Mockery::pattern('/credentials_expiry_buffer/'), Mockery::any()]);
    }

    public function test_env_non_numeric_credentials_expiry_buffer_reaches_validator(): void
    {
        $_SERVER['IAM_AUTH_CREDENTIALS_EXPIRY_BUFFER'] = 'oops';

        try {
            config()->set('iam-auth', require __DIR__.'/../config/iam-auth.php');

            $this->assertSame('oops', config('iam-auth.credentials_expiry_buffer'));

            Log::spy();
            (new IamAuthServiceProvider($this->app))->boot();

            Log::shouldHaveReceived('warning')
                ->once()
                ->withArgs(fn (string $message) => str_contains($message, 'must be numeric'));
        } finally {
            unset($_SERVER['IAM_AUTH_CREDENTIALS_EXPIRY_BUFFER']);
        }
    }
}
