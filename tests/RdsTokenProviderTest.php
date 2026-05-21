<?php

namespace Hackthebox\IamAuth\Tests;

use Aws\CacheInterface;
use Aws\Credentials\Credentials;
use Aws\Credentials\CredentialsInterface;
use Aws\Laravel\AwsServiceProvider;
use Aws\Rds\AuthTokenGenerator;
use GuzzleHttp\Promise\Create;
use Hackthebox\IamAuth\Cache\CachedCredentialProvider;
use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Support\Facades\Log;
use Mockery;
use Orchestra\Testbench\TestCase;
use RuntimeException;

class RdsTokenProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            AwsServiceProvider::class,
            IamAuthServiceProvider::class,
        ];
    }

    public function test_get_token_invokes_provider_and_signs(): void
    {
        $creds = new Credentials('AKIATEST', 'secret', null, time() + 3600);
        $rds = new RdsTokenProvider($this->makeProvider($creds));

        $token = $rds->getToken('db.example.aws', 3306, 'iam_user', 'eu-central-1');

        $this->assertIsString($token);
        $this->assertNotEmpty($token);
        $this->assertStringContainsString('db.example.aws:3306', $token);
    }

    public function test_signs_token_via_real_aws_sdk_without_mocking_generator(): void
    {
        $creds = new Credentials('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', null, time() + 3600);
        $rds = new RdsTokenProvider($this->makeProvider($creds));

        $token = $rds->getToken('my-rds.cluster.us-east-1.rds.amazonaws.com', 3306, 'app_user', 'us-east-1');

        $this->assertStringContainsString('my-rds.cluster.us-east-1.rds.amazonaws.com:3306', $token);
        $this->assertStringContainsString('DBUser=app_user', $token);
        $this->assertStringContainsString('X-Amz-Algorithm=AWS4-HMAC-SHA256', $token);
    }

    public function test_force_fresh_invalidates_then_refetches(): void
    {
        $creds = new Credentials('AKIA', 'secret', null, time() + 3600);
        $baseCalls = 0;
        $base = function () use (&$baseCalls, $creds) {
            $baseCalls++;
            return Create::promiseFor($creds);
        };

        $removeCalls = 0;
        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);
        $store->method('remove')->willReturnCallback(function () use (&$removeCalls) {
            $removeCalls++;
        });

        $provider = new CachedCredentialProvider($base, $store, 'test-key');
        $rds = new RdsTokenProvider($provider);

        $rds->getToken('h', 3306, 'u', 'r');
        $rds->getToken('h', 3306, 'u', 'r', forceFresh: true);

        $this->assertSame(2, $baseCalls, 'forceFresh must invalidate and re-fetch from base');
        $this->assertSame(1, $removeCalls, 'forceFresh must call store->remove');
    }

    public function test_get_token_without_force_fresh_does_not_invalidate(): void
    {
        $creds = new Credentials('AKIA', 'secret', null, time() + 3600);
        $base = static fn () => Create::promiseFor($creds);

        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);
        $store->expects($this->never())->method('remove');

        $provider = new CachedCredentialProvider($base, $store, 'test-key');
        $rds = new RdsTokenProvider($provider);

        $rds->getToken('h', 3306, 'u', 'r');
    }

    public function test_credential_snapshot_delegates_to_cached_provider(): void
    {
        $creds = new Credentials('AKIASNAP123', 'secret', null, time() + 1200);
        $base = static fn () => Create::promiseFor($creds);
        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);

        $provider = new CachedCredentialProvider($base, $store, 'test-key');
        $rds = new RdsTokenProvider($provider);

        $rds->getToken('h', 3306, 'u', 'r');

        $snapshot = $rds->credentialSnapshot();
        $this->assertTrue($snapshot['cred_present']);
        $this->assertSame('AKIASNAP', $snapshot['cred_access_key_prefix']);
    }

    public function test_debug_log_emitted_when_debug_config_true(): void
    {
        config(['iam-auth.debug' => true]);
        Log::spy();

        $creds = new Credentials('AKIADEBUG', 'secret', null, time() + 3600);
        $rds = new RdsTokenProvider($this->makeProvider($creds));

        $rds->getToken('h', 3306, 'u', 'r');

        Log::shouldHaveReceived('debug')
            ->with('iam-auth.token-access', Mockery::on(function ($payload) {
                return $payload['host'] === 'h'
                    && $payload['port'] === 3306
                    && $payload['force_fresh'] === false
                    && $payload['access_key_prefix'] === 'AKIADEBU';
            }))
            ->once();
    }

    public function test_generate_token_wraps_underlying_exception_with_context(): void
    {
        $creds = new Credentials('AKIAWRAP', 'secret', null, time() + 3600);
        $underlying = new RuntimeException('signing error');

        $rds = new class($this->makeProvider($creds), $underlying) extends RdsTokenProvider {
            public function __construct(
                CachedCredentialProvider $provider,
                private readonly RuntimeException $boom,
            ) {
                parent::__construct($provider);
            }

            protected function createAuthTokenGenerator(CredentialsInterface $credentials): AuthTokenGenerator
            {
                $gen = Mockery::mock(AuthTokenGenerator::class);
                $gen->shouldReceive('createToken')->andThrow($this->boom);
                return $gen;
            }
        };

        try {
            $rds->getToken('db.example.aws', 3306, 'iam_user', 'eu-central-1');
            $this->fail('expected RuntimeException');
        } catch (RuntimeException $e) {
            $this->assertSame(
                'Failed to generate RDS IAM auth token for iam_user@db.example.aws:3306 in region eu-central-1: signing error',
                $e->getMessage()
            );
            $this->assertSame($underlying, $e->getPrevious());
        }
    }

    public function test_debug_log_suppressed_when_debug_config_false(): void
    {
        config(['iam-auth.debug' => false]);
        Log::spy();

        $creds = new Credentials('AKIATESTVALUE', 'secret', null, time() + 3600);
        $rds = new RdsTokenProvider($this->makeProvider($creds));

        $rds->getToken('h', 3306, 'u', 'r');

        Log::shouldNotHaveReceived('debug');
    }

    private function makeProvider(Credentials $creds): CachedCredentialProvider
    {
        $base = static fn () => Create::promiseFor($creds);
        $store = $this->createMock(CacheInterface::class);
        $store->method('get')->willReturn(null);

        return new CachedCredentialProvider($base, $store, 'test-key');
    }
}
