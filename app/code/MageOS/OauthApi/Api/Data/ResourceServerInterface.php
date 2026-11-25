<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api\Data;

/**
 * An API that accepts tokens issued by the authorization server (RFC 8707 resource, RFC 9728 protected resource).
 *
 * @api
 */
interface ResourceServerInterface
{
    /**
     * Path relative to the store base URL, starting with "/"
     */
    public function getPath(): string;

    public function getLabel(): string;

    /**
     * @return ScopeInterface[] keyed by scope name
     */
    public function getScopes(): array;
}
