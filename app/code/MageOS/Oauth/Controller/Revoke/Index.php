<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller\Revoke;

use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\CsrfAwareActionInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\Request\InvalidRequestException;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\ResultInterface;
use MageOS\Oauth\Http\Psr7Bridge;
use MageOS\Oauth\Model\Config;
use MageOS\Oauth\Model\Repository\ClientRepository;
use MageOS\Oauth\Model\TokenRevocation;

/**
 * RFC 7009 revocation endpoint.
 */
class Index implements HttpPostActionInterface, CsrfAwareActionInterface
{
    public function __construct(
        private readonly HttpRequest $request,
        private readonly Config $config,
        private readonly ClientRepository $clientRepository,
        private readonly TokenRevocation $tokenRevocation,
        private readonly Psr7Bridge $bridge
    ) {
    }

    public function execute(): ResultInterface
    {
        if (!$this->config->isEnabled()) {
            return $this->bridge->json(404, ['error' => 'not_found']);
        }

        [$clientId, $clientSecret] = $this->getClientCredentials();
        if ($clientId === null || !$this->clientRepository->validateClient($clientId, $clientSecret, null)) {
            return $this->bridge->json(401, ['error' => 'invalid_client']);
        }

        $token = $this->request->getPost('token');
        if (!is_string($token) || $token === '') {
            return $this->bridge->json(400, ['error' => 'invalid_request']);
        }
        $this->tokenRevocation->revoke($token, $clientId);

        return $this->bridge->json(200, []);
    }

    /**
     * @return array{0: ?string, 1: ?string}
     */
    private function getClientCredentials(): array
    {
        $header = (string)$this->request->getHeader('Authorization');
        if (stripos($header, 'Basic ') === 0) {
            $decoded = base64_decode(substr($header, 6), true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$id, $secret] = explode(':', $decoded, 2);

                return [urldecode($id), urldecode($secret)];
            }
        }
        $id = $this->request->getPost('client_id');
        $secret = $this->request->getPost('client_secret');

        return [is_string($id) ? $id : null, is_string($secret) ? $secret : null];
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
