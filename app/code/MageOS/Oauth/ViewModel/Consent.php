<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\ViewModel;

use Magento\Backend\Model\UrlInterface;
use Magento\Framework\View\Element\Block\ArgumentInterface;
use MageOS\Oauth\Model\Consent\PendingAuthorization;
use MageOS\OauthApi\Api\Data\ScopeInterface;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;

class Consent implements ArgumentInterface
{
    public function __construct(
        private readonly PendingAuthorization $pending,
        private readonly ResourceServerRegistryInterface $registry,
        private readonly UrlInterface $url
    ) {
    }

    public function getClientName(): string
    {
        return (string)$this->pending->getRequest()?->getClient()->getName();
    }

    public function getClientId(): string
    {
        return (string)$this->pending->getRequest()?->getClient()->getIdentifier();
    }

    /**
     * Host of the redirect URI, or the scheme for a native app, so the admin judges where the code goes
     */
    public function getRedirectTarget(): string
    {
        $request = $this->pending->getRequest();
        $uri = $request?->getRedirectUri() ?? (array)$request?->getClient()->getRedirectUri();
        $uri = is_array($uri) ? (string)reset($uri) : (string)$uri;
        $parts = parse_url($uri) ?: [];

        return (string)($parts['host'] ?? (($parts['scheme'] ?? '') . ':'));
    }

    public function getResourceLabel(): string
    {
        return (string)$this->pending->getResourceServer()?->getLabel();
    }

    public function getResourceUri(): string
    {
        $resourceServer = $this->pending->getResourceServer();

        return $resourceServer === null ? '' : $this->registry->getUri($resourceServer);
    }

    /**
     * @return ScopeInterface[]
     */
    public function getGrantableScopes(): array
    {
        return $this->pending->getGrantable();
    }

    /**
     * @return string[]
     */
    public function getRefusedScopes(): array
    {
        return $this->pending->getRefused();
    }

    public function getDecideUrl(): string
    {
        return $this->url->getUrl('mageos_oauth/consent/decide');
    }
}
