<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller\Register;

use InvalidArgumentException;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\CsrfAwareActionInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\Request\InvalidRequestException;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\ResultInterface;
use MageOS\Oauth\Http\Psr7Bridge;
use MageOS\Oauth\Model\ClientRegistration;
use MageOS\Oauth\Model\Config;

/**
 * RFC 7591 dynamic client registration endpoint.
 */
class Index implements HttpPostActionInterface, CsrfAwareActionInterface
{
    private const MAX_BODY_BYTES = 16384;

    public function __construct(
        private readonly HttpRequest $request,
        private readonly Config $config,
        private readonly ClientRegistration $clientRegistration,
        private readonly Psr7Bridge $bridge
    ) {
    }

    public function execute(): ResultInterface
    {
        if (!$this->config->isEnabled() || !$this->config->isDynamicRegistrationEnabled()) {
            return $this->bridge->json(404, ['error' => 'not_found']);
        }

        $body = (string)$this->request->getContent();
        try {
            $metadata = strlen($body) <= self::MAX_BODY_BYTES
                ? json_decode($body, true, 8, JSON_THROW_ON_ERROR)
                : null;
        } catch (\JsonException) {
            $metadata = null;
        }
        if (!is_array($metadata)) {
            return $this->bridge->json(400, ['error' => ClientRegistration::ERROR_METADATA]);
        }

        try {
            return $this->bridge->json(201, $this->clientRegistration->register($metadata));
        } catch (InvalidArgumentException $e) {
            return $this->bridge->json(400, ['error' => $e->getMessage()]);
        }
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
