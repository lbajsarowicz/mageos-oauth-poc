<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Principal;

use MageOS\OauthApi\Api\PrincipalAuthorizerInterface;

/**
 * Dispatches by principal type ("admin" in "admin:5"). A type without an authorizer is denied.
 */
class PrincipalAuthorizerPool implements PrincipalAuthorizerInterface
{
    /**
     * @param PrincipalAuthorizerInterface[] $authorizers keyed by principal type
     */
    public function __construct(
        private readonly array $authorizers = []
    ) {
    }

    public function isActive(string $principal): bool
    {
        return $this->get($principal)?->isActive($principal) ?? false;
    }

    public function isAllowed(string $principal, string $aclResource): bool
    {
        return $this->get($principal)?->isAllowed($principal, $aclResource) ?? false;
    }

    private function get(string $principal): ?PrincipalAuthorizerInterface
    {
        $type = strstr($principal, ':', true);

        return $type === false ? null : ($this->authorizers[$type] ?? null);
    }
}
