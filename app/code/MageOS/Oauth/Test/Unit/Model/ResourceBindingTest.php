<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Test\Unit\Model;

use League\OAuth2\Server\Exception\OAuthServerException;
use LogicException;
use MageOS\Oauth\Model\ResourceBinding;
use PHPUnit\Framework\TestCase;

class ResourceBindingTest extends TestCase
{
    public function testStoredResourceIsBoundWhenNoneRequested(): void
    {
        $binding = new ResourceBinding();
        $binding->request(null);
        $binding->bindTo('https://shop.example.com/rest');

        $this->assertSame('https://shop.example.com/rest', $binding->getBound());
    }

    public function testMatchingRequestIsBound(): void
    {
        $binding = new ResourceBinding();
        $binding->request('https://shop.example.com/rest');
        $binding->bindTo('https://shop.example.com/rest');

        $this->assertSame('https://shop.example.com/rest', $binding->getBound());
    }

    public function testMismatchIsInvalidTarget(): void
    {
        $binding = new ResourceBinding();
        $binding->request('https://shop.example.com/mcp');

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionMessage('does not match');
        $binding->bindTo('https://shop.example.com/rest');
    }

    public function testNothingBoundFailsClosed(): void
    {
        $binding = new ResourceBinding();
        $binding->request('https://shop.example.com/rest');

        $this->expectException(LogicException::class);
        $binding->getBound();
    }
}
