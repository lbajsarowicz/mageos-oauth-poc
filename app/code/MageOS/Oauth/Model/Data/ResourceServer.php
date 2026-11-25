<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Data;

use MageOS\OauthApi\Api\Data\ResourceServerInterface;
use MageOS\OauthApi\Api\Data\ScopeInterface;

class ResourceServer implements ResourceServerInterface
{
    /**
     * @param ScopeInterface[] $scopes
     */
    public function __construct(
        private readonly string $path,
        private readonly string $label,
        private readonly array $scopes
    ) {
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getLabel(): string
    {
        return $this->label;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }
}
