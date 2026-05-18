<?php

namespace Hackthebox\IamAuth\Tests;

use Hackthebox\IamAuth\IamAuthServiceProvider;
use Hackthebox\IamAuth\RdsTokenProvider;
use Illuminate\Support\Facades\Log;
use Orchestra\Testbench\TestCase;

class RdsTokenProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            \Aws\Laravel\AwsServiceProvider::class,
            IamAuthServiceProvider::class,
        ];
    }

    public function test_get_token_invokes_provider_and_signs(): void
    {
        $creds = new \Aws\Credentials\Credentials('AKIATEST', 'secret', null, time() + 3600);
        $provider = fn () => \GuzzleHttp\Promise\Create::promiseFor($creds);

        $rds = new \Hackthebox\IamAuth\RdsTokenProvider($provider, $provider);

        $token = $rds->getToken('db.example.aws', 3306, 'iam_user', 'eu-central-1');

        $this->assertIsString($token);
        $this->assertNotEmpty($token);
        $this->assertStringContainsString('db.example.aws:3306', $token);
    }

    public function test_force_fresh_uses_fresh_provider_not_cached(): void
    {
        $cachedCalls = 0;
        $freshCalls = 0;
        $creds = new \Aws\Credentials\Credentials('AKIA', 'secret', null, time() + 3600);

        $cached = function () use (&$cachedCalls, $creds) {
            $cachedCalls++;
            return \GuzzleHttp\Promise\Create::promiseFor($creds);
        };
        $fresh = function () use (&$freshCalls, $creds) {
            $freshCalls++;
            return \GuzzleHttp\Promise\Create::promiseFor($creds);
        };

        $rds = new \Hackthebox\IamAuth\RdsTokenProvider($cached, $fresh);

        $rds->getToken('h', 3306, 'u', 'r');
        $rds->getToken('h', 3306, 'u', 'r', forceFresh: true);

        $this->assertSame(1, $cachedCalls);
        $this->assertSame(1, $freshCalls);
    }

    public function test_debug_log_emitted_when_debug_config_true(): void
    {
        config(['iam-auth.debug' => true]);
        \Illuminate\Support\Facades\Log::spy();

        $creds = new \Aws\Credentials\Credentials('AKIADEBUG', 'secret', null, time() + 3600);
        $provider = fn () => \GuzzleHttp\Promise\Create::promiseFor($creds);
        $rds = new \Hackthebox\IamAuth\RdsTokenProvider($provider, $provider);

        $rds->getToken('h', 3306, 'u', 'r');

        \Illuminate\Support\Facades\Log::shouldHaveReceived('debug')
            ->with('iam-auth.token-access', \Mockery::on(function ($payload) {
                return $payload['host'] === 'h'
                    && $payload['port'] === 3306
                    && $payload['force_fresh'] === false
                    && $payload['access_key_prefix'] === 'AKIADEBU';
            }))
            ->once();
    }

    public function test_debug_log_suppressed_when_debug_config_false(): void
    {
        config(['iam-auth.debug' => false]);
        \Illuminate\Support\Facades\Log::spy();

        $creds = new \Aws\Credentials\Credentials('AKIATESTVALUE', 'secret', null, time() + 3600);
        $provider = fn () => \GuzzleHttp\Promise\Create::promiseFor($creds);
        $rds = new \Hackthebox\IamAuth\RdsTokenProvider($provider, $provider);

        $rds->getToken('h', 3306, 'u', 'r');

        \Illuminate\Support\Facades\Log::shouldNotHaveReceived('debug');
    }
}
