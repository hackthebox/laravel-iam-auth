<?php

namespace Hackthebox\IamAuth;

use Aws\Credentials\CredentialProvider;
use Aws\Sdk;
use GuzzleHttp\Promise\Create;
use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use RuntimeException;

class IamAuthServiceProvider extends ServiceProvider
{
    private const BUNDLED_CA_PATH = __DIR__.'/../resources/certs/global-bundle.pem';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/iam-auth.php', 'iam-auth');

        $this->app->singleton(AwsCredentialCache::class);

        $this->app->singleton('iam-auth.credential-provider', function ($app) {
            $cache = $app->make(AwsCredentialCache::class);
            $provider = $this->buildCredentialProvider();

            return function () use ($cache, $provider) {
                try {
                    return Create::promiseFor(
                        $cache->resolve(fn () => $provider()->wait())
                    );
                } catch (\Throwable $e) {
                    return Create::rejectionFor($e);
                }
            };
        });

        $this->app->extend('aws', function (Sdk $sdk, Application $app) {
            $config = $app->make('config')->get('aws');
            $config['credentials'] = $app->make('iam-auth.credential-provider');

            return new Sdk($config);
        });

        $this->app->bind(RdsTokenProvider::class, function ($app) {
            return new RdsTokenProvider($app->make('iam-auth.credential-provider'));
        });

        $this->app->bind('db.connector.mysql', IamMySqlConnector::class);
        $this->app->bind('db.connector.mariadb', IamMariaDbConnector::class);
        $this->app->bind('db.connector.pgsql', IamPostgresConnector::class);
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

    private function buildCredentialProvider(): callable
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
