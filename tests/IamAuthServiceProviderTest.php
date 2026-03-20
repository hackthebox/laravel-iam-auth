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
        return [IamAuthServiceProvider::class];
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
}
