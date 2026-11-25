<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api\Data;

/**
 * @api
 */
interface ScopeInterface
{
    public function getName(): string;

    public function getDescription(): string;

    /**
     * ACL resource the principal needs to be granted this scope; null when the principal's role alone decides
     */
    public function getAclResource(): ?string;
}
