<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Test\Unit\Model;

use League\OAuth2\Server\Exception\OAuthServerException;
use MageOS\Oauth\Model\AuthorizeRequestGuard;
use MageOS\OauthApi\Api\Data\ResourceServerInterface;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AuthorizeRequestGuardTest extends TestCase
{
    private const RESOURCE = 'https://shop.example.com/rest';

    private AuthorizeRequestGuard $guard;

    protected function setUp(): void
    {
        $registry = $this->createStub(ResourceServerRegistryInterface::class);
        $registry->method('getByUri')->willReturnCallback(
            fn (string $uri) => $uri === self::RESOURCE ? $this->createStub(ResourceServerInterface::class) : null
        );
        $this->guard = new AuthorizeRequestGuard($registry);
    }

    public function testValidRequestReturnsResource(): void
    {
        $this->assertSame(self::RESOURCE, $this->guard->assertValid($this->query()));
    }

    #[DataProvider('invalidRequests')]
    public function testInvalidRequestIsRejected(array $override, string $errorType): void
    {
        try {
            $this->guard->assertValid(array_merge($this->query(), $override));
            $this->fail('The request was accepted.');
        } catch (OAuthServerException $e) {
            $this->assertSame($errorType, $e->getErrorType());
        }
    }

    public static function invalidRequests(): array
    {
        return [
            'implicit flow' => [['response_type' => 'token'], 'unsupported_response_type'],
            'no PKCE' => [['code_challenge' => ''], 'invalid_request'],
            'plain PKCE' => [['code_challenge_method' => 'plain'], 'invalid_request'],
            'no resource' => [['resource' => ''], 'invalid_target'],
            'unknown resource' => [['resource' => 'https://evil.example.com/rest'], 'invalid_target'],
            'repeated resource' => [
                ['resource' => [self::RESOURCE, 'https://shop.example.com/mcp']],
                'invalid_request',
            ],
        ];
    }

    public function testFilterKeepsOnlyAuthorizationParameters(): void
    {
        $this->assertSame(
            ['client_id' => 'abc'],
            $this->guard->filter(['client_id' => 'abc', 'foo' => 'bar', 'scope' => ['x']])
        );
    }

    private function query(): array
    {
        return [
            'response_type' => 'code',
            'client_id' => 'abc',
            'code_challenge' => str_repeat('a', 43),
            'code_challenge_method' => 'S256',
            'resource' => self::RESOURCE,
        ];
    }
}
