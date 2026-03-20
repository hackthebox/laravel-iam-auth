<?php

namespace Hackthebox\IamAuth;

use Hackthebox\IamAuth\Connectors\IamMariaDbConnector;
use Hackthebox\IamAuth\Connectors\IamMySqlConnector;
use Hackthebox\IamAuth\Connectors\IamPostgresConnector;
use Illuminate\Support\ServiceProvider;

class IamAuthServiceProvider extends ServiceProvider
{
    private const BUNDLED_CA_PATH = __DIR__.'/../resources/certs/global-bundle.pem';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/iam-auth.php', 'iam-auth');

        $this->app->singleton(AwsCredentialCache::class);

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
}
