<?php

namespace Hackthebox\RdsIamAuth;

use Hackthebox\RdsIamAuth\Connectors\RdsIamMariaDbConnector;
use Hackthebox\RdsIamAuth\Connectors\RdsIamMySqlConnector;
use Hackthebox\RdsIamAuth\Connectors\RdsIamPostgresConnector;
use Illuminate\Support\ServiceProvider;

class RdsIamAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/rds-iam-auth.php', 'rds-iam-auth');

        $this->app->bind('db.connector.mysql', RdsIamMySqlConnector::class);
        $this->app->bind('db.connector.mariadb', RdsIamMariaDbConnector::class);
        $this->app->bind('db.connector.pgsql', RdsIamPostgresConnector::class);
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/rds-iam-auth.php' => config_path('rds-iam-auth.php'),
        ], 'rds-iam-auth-config');
    }
}
