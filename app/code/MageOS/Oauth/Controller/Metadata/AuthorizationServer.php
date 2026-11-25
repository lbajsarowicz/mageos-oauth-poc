<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller\Metadata;

use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\Controller\ResultInterface;
use MageOS\Oauth\Http\Psr7Bridge;
use MageOS\Oauth\Model\Config;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;

/**
 * RFC 8414 authorization server metadata, served at /.well-known/oauth-authorization-server.
 */
class AuthorizationServer implements HttpGetActionInterface
{
    public function __construct(
        private readonly Config $config,
        private readonly ResourceServerRegistryInterface $registry,
        private readonly Psr7Bridge $bridge
    ) {
    }

    public function execute(): ResultInterface
    {
        if (!$this->config->isEnabled()) {
            return $this->bridge->json(404, ['error' => 'not_found']);
        }

        $issuer = $this->config->getIssuer();
        $scopes = [];
        foreach ($this->registry->getAll() as $resourceServer) {
            array_push($scopes, ...array_keys($resourceServer->getScopes()));
        }

        $metadata = [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer . '/oauth2/authorize',
            'token_endpoint' => $issuer . '/oauth2/token',
            'revocation_endpoint' => $issuer . '/oauth2/revoke',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none', 'client_secret_post', 'client_secret_basic'],
            'revocation_endpoint_auth_methods_supported' => ['none', 'client_secret_post', 'client_secret_basic'],
            'scopes_supported' => array_values(array_unique($scopes)),
        ];
        if ($this->config->isDynamicRegistrationEnabled()) {
            $metadata['registration_endpoint'] = $issuer . '/oauth2/register';
        }

        return $this->bridge->json(200, $metadata);
    }
}
