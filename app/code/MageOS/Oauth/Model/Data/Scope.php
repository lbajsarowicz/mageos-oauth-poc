<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Data;

use MageOS\OauthApi\Api\Data\ScopeInterface;

class Scope implements ScopeInterface
{
    public function __construct(
        private readonly string $name,
        private readonly string $description,
        private readonly ?string $aclResource
    ) {
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getAclResource(): ?string
    {
        return $this->aclResource;
    }
}
