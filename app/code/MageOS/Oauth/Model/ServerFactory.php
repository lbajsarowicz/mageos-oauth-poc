<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use MageOS\Oauth\Model\Repository\AccessTokenRepository;
use MageOS\Oauth\Model\Repository\AuthCodeRepository;
use MageOS\Oauth\Model\Repository\ClientRepository;
use MageOS\Oauth\Model\Repository\RefreshTokenRepository;
use MageOS\Oauth\Model\Repository\ScopeRepository;

/**
 * Builds the league/oauth2-server objects on first use. Only the authorization code grant (with PKCE) and the
 * refresh token grant are enabled.
 */
class ServerFactory
{
    private ?AuthorizationServer $authorizationServer = null;

    private ?ResourceServer $resourceServer = null;

    public function __construct(
        private readonly Config $config,
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly AuthCodeRepository $authCodeRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository
    ) {
    }

    public function getAuthorizationServer(): AuthorizationServer
    {
        if ($this->authorizationServer !== null) {
            return $this->authorizationServer;
        }

        $server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            new CryptKey($this->config->getPrivateKey(), null, false),
            $this->getEncryptionKey()
        );

        $authCodeGrant = new AuthCodeGrant(
            $this->authCodeRepository,
            $this->refreshTokenRepository,
            $this->config->getAuthCodeLifetime()
        );
        $authCodeGrant->setRefreshTokenTTL($this->config->getRefreshTokenLifetime());
        $server->enableGrantType($authCodeGrant, $this->config->getAccessTokenLifetime());

        $refreshTokenGrant = new RefreshTokenGrant($this->refreshTokenRepository);
        $refreshTokenGrant->setRefreshTokenTTL($this->config->getRefreshTokenLifetime());
        $server->enableGrantType($refreshTokenGrant, $this->config->getAccessTokenLifetime());

        return $this->authorizationServer = $server;
    }

    public function getResourceServer(): ResourceServer
    {
        return $this->resourceServer ??= new ResourceServer(
            $this->accessTokenRepository,
            new CryptKey($this->config->getPublicKey(), null, false)
        );
    }

    public function getEncryptionKey(): Key
    {
        return Key::loadFromAsciiSafeString($this->config->getEncryptionKey());
    }
}
