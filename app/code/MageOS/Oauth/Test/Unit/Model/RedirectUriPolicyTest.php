<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Test\Unit\Model;

use MageOS\Oauth\Model\RedirectUriPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class RedirectUriPolicyTest extends TestCase
{
    #[DataProvider('uris')]
    public function testIsAllowed(string $uri, bool $expected): void
    {
        $this->assertSame($expected, (new RedirectUriPolicy())->isAllowed($uri));
    }

    public static function uris(): array
    {
        return [
            'https' => ['https://client.example.com/callback', true],
            'loopback ipv4' => ['http://127.0.0.1:33418/callback', true],
            'loopback name' => ['http://localhost/callback', true],
            'loopback ipv6' => ['http://[::1]:8080/cb', true],
            'native app scheme' => ['cursor://anysphere.cursor-mcp/oauth/callback', true],
            'plain http remote' => ['http://client.example.com/callback', false],
            'fragment' => ['https://client.example.com/callback#x', false],
            'credentials' => ['https://user:pass@client.example.com/callback', false],
            'javascript' => ['javascript:alert(1)', false],
            'data' => ['data:text/html,<script>alert(1)</script>', false],
            'whitespace' => ["https://client.example.com/\ncallback", false],
            'no scheme' => ['//client.example.com/callback', false],
            'empty' => ['', false],
        ];
    }
}
