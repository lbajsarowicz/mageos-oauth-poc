<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller\Metadata;

use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\ResultInterface;
use MageOS\Oauth\Http\Psr7Bridge;
use MageOS\Oauth\Model\Config;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;

/**
 * RFC 9728 protected resource metadata for every registered resource server, served at
 * /.well-known/oauth-protected-resource/<resource path>.
 */
class ProtectedResource implements HttpGetActionInterface
{
    public const PARAM_RESOURCE_PATH = 'resource_path';

    public function __construct(
        private readonly RequestInterface $request,
        private readonly Config $config,
        private readonly ResourceServerRegistryInterface $registry,
        private readonly Psr7Bridge $bridge
    ) {
    }

    public function execute(): ResultInterface
    {
        $resourceServer = $this->registry->getByPath((string)$this->request->getParam(self::PARAM_RESOURCE_PATH));
        if (!$this->config->isEnabled() || $resourceServer === null) {
            return $this->bridge->json(404, ['error' => 'not_found']);
        }

        return $this->bridge->json(200, [
            'resource' => $this->registry->getUri($resourceServer),
            'resource_name' => $resourceServer->getLabel(),
            'authorization_servers' => [$this->config->getIssuer()],
            'scopes_supported' => array_keys($resourceServer->getScopes()),
            'bearer_methods_supported' => ['header'],
        ]);
    }
}
