<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Consent;

use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use MageOS\OauthApi\Api\Data\ResourceServerInterface;
use MageOS\OauthApi\Api\Data\ScopeInterface;

/**
 * The authorization request being shown on the consent screen, shared between the controller and the view model.
 */
class PendingAuthorization
{
    private ?AuthorizationRequestInterface $request = null;

    private ?ResourceServerInterface $resourceServer = null;

    /**
     * @var ScopeInterface[]
     */
    private array $grantable = [];

    /**
     * @var string[]
     */
    private array $refused = [];

    /**
     * @param ScopeInterface[] $grantable
     * @param string[] $refused
     */
    public function set(
        AuthorizationRequestInterface $request,
        ResourceServerInterface $resourceServer,
        array $grantable,
        array $refused
    ): void {
        $this->request = $request;
        $this->resourceServer = $resourceServer;
        $this->grantable = $grantable;
        $this->refused = $refused;
    }

    public function getRequest(): ?AuthorizationRequestInterface
    {
        return $this->request;
    }

    public function getResourceServer(): ?ResourceServerInterface
    {
        return $this->resourceServer;
    }

    /**
     * @return ScopeInterface[]
     */
    public function getGrantable(): array
    {
        return $this->grantable;
    }

    /**
     * @return string[]
     */
    public function getRefused(): array
    {
        return $this->refused;
    }
}
