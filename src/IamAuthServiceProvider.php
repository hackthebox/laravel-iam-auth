<?php

namespace Hackthebox\IamAuth;

use Aws\CacheInterface;
use Aws\Credentials\CredentialProvider;
use GuzzleHttp\Promise\PromiseInterface;
use Hackthebox\IamAuth\Cache\AwsCredentialCacheStore;
use Hackthebox\IamAuth\Cache\CachedCredentialProvider;
use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Illuminate\Support\ServiceProvider;
use RuntimeException;

class IamAuthServiceProvider extends ServiceProvider
{
    private const BUNDLED_CA_PATH = __DIR__.'/../resources/certs/global-bundle.pem';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/iam-auth.php', 'iam-auth');

        $this->app->singleton(CacheInterface::class, AwsCredentialCacheStore::class);

        $this->app->singleton(CachedCredentialProvider::class, function ($app) {
            $base = $this->buildBaseProvider();
            return new CachedCredentialProvider(
                static fn () => $base(),
                $app->make(CacheInterface::class),
                AwsCredentialCacheStore::CACHE_KEY,
            );
        });

        config(['aws.credentials' => [self::class, 'resolveCredentialsForSdk']]);

        $this->app->bind(RdsTokenProvider::class, function ($app) {
            return new RdsTokenProvider($app->make(CachedCredentialProvider::class));
        });

        $this->app->bind('db.connector.mysql', function ($app) {
            return new IamMySqlConnector($app->make(RdsTokenProvider::class));
        });
        $this->app->bind('db.connector.mariadb', function ($app) {
            return new IamMariaDbConnector($app->make(RdsTokenProvider::class));
        });
        $this->app->bind('db.connector.pgsql', function ($app) {
            return new IamPostgresConnector($app->make(RdsTokenProvider::class));
        });
    }

    public static function resolveCredentialsForSdk(): PromiseInterface
    {
        return app(CachedCredentialProvider::class)();
    }

    public function boot(): void
    {
        if (empty(config('iam-auth.ssl_ca_path'))) {
            config(['iam-auth.ssl_ca_path' => self::BUNDLED_CA_PATH]);
        }

        $this->publishes([
            __DIR__.'/../config/iam-auth.php' => config_path('iam-auth.php'),
        ], 'iam-auth-config');
    }

    private function buildBaseProvider(): callable
    {
        $name = config('iam-auth.credential_provider', 'default');

        return match ($name) {
            'default' => CredentialProvider::defaultProvider(),
            'environment' => CredentialProvider::env(),
            'ecs' => CredentialProvider::ecsCredentials(),
            'web_identity' => CredentialProvider::assumeRoleWithWebIdentityCredentialProvider(),
            'instance_profile' => CredentialProvider::instanceProfile(),
            'sso' => CredentialProvider::sso(),
            'ini' => CredentialProvider::ini(),
            default => throw new RuntimeException(
                "Unsupported IAM auth credential provider '$name'. "
                ."Supported values: default, environment, ecs, web_identity, instance_profile, sso, ini."
            ),
        };
    }
}
