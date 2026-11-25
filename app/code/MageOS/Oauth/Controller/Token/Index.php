<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller\Token;

use League\OAuth2\Server\Exception\OAuthServerException;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\CsrfAwareActionInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\Request\InvalidRequestException;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\ResultInterface;
use MageOS\Oauth\Http\Psr7Bridge;
use MageOS\Oauth\Model\Config;
use MageOS\Oauth\Model\ResourceBinding;
use MageOS\Oauth\Model\ServerFactory;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;
use Psr\Log\LoggerInterface;

/**
 * Token endpoint for the authorization_code and refresh_token grants. Clients authenticate with their own
 * credentials or PKCE, so the storefront form key does not apply.
 */
class Index implements HttpPostActionInterface, CsrfAwareActionInterface
{
    public function __construct(
        private readonly HttpRequest $request,
        private readonly Config $config,
        private readonly ServerFactory $serverFactory,
        private readonly ResourceBinding $resourceBinding,
        private readonly ResourceServerRegistryInterface $registry,
        private readonly Psr7Bridge $bridge,
        private readonly LoggerInterface $logger
    ) {
    }

    public function execute(): ResultInterface
    {
        if (!$this->config->isEnabled()) {
            return $this->bridge->json(404, ['error' => 'not_found']);
        }

        $resource = $this->request->getPost('resource');
        if ($resource !== null && (!is_string($resource) || $this->registry->getByUri($resource) === null)) {
            return $this->bridge->json(400, ['error' => 'invalid_target']);
        }
        $this->resourceBinding->request($resource);

        try {
            $response = $this->serverFactory->getAuthorizationServer()->respondToAccessTokenRequest(
                $this->bridge->toServerRequest($this->request),
                $this->bridge->createResponse()
            );
        } catch (OAuthServerException $e) {
            $response = $e->generateHttpResponse($this->bridge->createResponse());
        } catch (\Throwable $e) {
            $this->logger->error('OAuth token request failed', ['exception' => $e]);

            return $this->bridge->json(500, ['error' => 'server_error']);
        }

        return $this->bridge->toResult($response);
    }

    public function createCsrfValidationException(RequestInterface $request): ?InvalidRequestException
    {
        return null;
    }

    public function validateForCsrf(RequestInterface $request): ?bool
    {
        return true;
    }
}
