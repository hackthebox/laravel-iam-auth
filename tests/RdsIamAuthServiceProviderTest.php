<?php

namespace Hackthebox\RdsIamAuth\Tests;

use Hackthebox\RdsIamAuth\Connectors\RdsIamMariaDbConnector;
use Hackthebox\RdsIamAuth\Connectors\RdsIamMySqlConnector;
use Hackthebox\RdsIamAuth\Connectors\RdsIamPostgresConnector;
use Hackthebox\RdsIamAuth\RdsIamAuthServiceProvider;
use Orchestra\Testbench\TestCase;

class RdsIamAuthServiceProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [RdsIamAuthServiceProvider::class];
    }

    public function test_registers_mysql_connector(): void
    {
        $this->assertInstanceOf(
            RdsIamMySqlConnector::class,
            $this->app->make('db.connector.mysql')
        );
    }

    public function test_registers_mariadb_connector(): void
    {
        $this->assertInstanceOf(
            RdsIamMariaDbConnector::class,
            $this->app->make('db.connector.mariadb')
        );
    }

    public function test_registers_pgsql_connector(): void
    {
        $this->assertInstanceOf(
            RdsIamPostgresConnector::class,
            $this->app->make('db.connector.pgsql')
        );
    }

    public function test_merges_config(): void
    {
        $this->assertNotNull(config('rds-iam-auth.region'));
        $this->assertSame(600, config('rds-iam-auth.cache_ttl'));
        $this->assertStringEndsWith('resources/certs/global-bundle.pem', config('rds-iam-auth.ssl_ca_path'));
    }
}
