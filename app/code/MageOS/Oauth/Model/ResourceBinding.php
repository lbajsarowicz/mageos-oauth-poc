<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use League\OAuth2\Server\Exception\OAuthServerException;
use LogicException;

/**
 * Carries the RFC 8707 resource of the grant being processed through league/oauth2-server, which has no notion of
 * resource indicators. The token endpoint records the requested resource; the code and refresh-token repositories
 * bind the stored one and refuse a mismatch; token persistence reads the bound value.
 */
class ResourceBinding
{
    private ?string $requested = null;

    private ?string $bound = null;

    public function request(?string $resourceUri): void
    {
        $this->requested = $resourceUri;
        $this->bound = null;
    }

    /**
     * @throws OAuthServerException
     */
    public function bindTo(string $storedResourceUri): void
    {
        if ($this->requested !== null && $this->requested !== $storedResourceUri) {
            throw new OAuthServerException(
                'The requested resource does not match the grant.',
                3,
                'invalid_target',
                400
            );
        }
        $this->bound = $storedResourceUri;
    }

    public function getBound(): string
    {
        if ($this->bound === null) {
            throw new LogicException('No resource is bound to the current grant.');
        }

        return $this->bound;
    }
}
