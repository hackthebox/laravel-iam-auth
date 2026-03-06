<?php

namespace Hackthebox\RdsIamAuth\Tests;

use Aws\Rds\AuthTokenGenerator;
use Hackthebox\RdsIamAuth\RdsAuthTokenProvider;
use Hackthebox\RdsIamAuth\RdsIamAuthServiceProvider;
use Mockery;
use Orchestra\Testbench\TestCase;

class RdsAuthTokenProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [RdsIamAuthServiceProvider::class];
    }

    public function test_generates_token_via_aws_sdk(): void
    {
        $generator = Mockery::mock(AuthTokenGenerator::class);
        $generator->shouldReceive('createToken')
            ->once()
            ->with('my-rds.cluster.us-east-1.rds.amazonaws.com:3306', 'us-east-1', 'app_user')
            ->andReturn('generated-iam-token');

        $provider = Mockery::mock(RdsAuthTokenProvider::class)
            ->makePartial()
            ->shouldAllowMockingProtectedMethods();

        $provider->shouldReceive('createTokenGenerator')
            ->once()
            ->andReturn($generator);

        $token = $provider->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');

        $this->assertSame('generated-iam-token', $token);
    }
}
