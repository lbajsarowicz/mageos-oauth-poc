<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthWebapi\Model;

use Magento\Authorization\Model\UserContextInterface;
use Magento\Framework\Webapi\Request;
use MageOS\OauthApi\Api\Exception\InvalidTokenException;
use MageOS\OauthApi\Api\TokenValidatorInterface;

/**
 * Authenticates REST calls that carry a Mage-OS OAuth access token for the "/rest" resource with the "webapi"
 * scope. Any other bearer token is left to the next user context, so integration and admin tokens keep working.
 */
class OauthUserContext implements UserContextInterface
{
    public const RESOURCE_PATH = '/rest';
    public const SCOPE = 'webapi';

    private bool $resolved = false;

    private ?int $userId = null;

    public function __construct(
        private readonly Request $request,
        private readonly TokenValidatorInterface $tokenValidator
    ) {
    }

    public function getUserId()
    {
        $this->resolve();

        return $this->userId;
    }

    public function getUserType()
    {
        $this->resolve();

        return $this->userId === null ? null : UserContextInterface::USER_TYPE_ADMIN;
    }

    private function resolve(): void
    {
        if ($this->resolved) {
            return;
        }
        $this->resolved = true;

        $header = (string)$this->request->getHeader('Authorization');
        if (preg_match('/^Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)$/', $header, $matches) !== 1) {
            return;
        }

        try {
            $token = $this->tokenValidator->validate($matches[1], self::RESOURCE_PATH);
        } catch (InvalidTokenException) {
            return;
        }
        if ($token->getPrincipalType() === 'admin' && ctype_digit($token->getPrincipalId())
            && $token->hasScope(self::SCOPE)) {
            $this->userId = (int)$token->getPrincipalId();
        }
    }
}
