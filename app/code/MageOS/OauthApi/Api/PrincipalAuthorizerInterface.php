<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api;

/**
 * Answers authorization questions about a principal outside of its own session.
 *
 * Principals are written as "<type>:<id>", for example "admin:5". Unknown types are denied.
 *
 * @api
 */
interface PrincipalAuthorizerInterface
{
    public function isActive(string $principal): bool;

    public function isAllowed(string $principal, string $aclResource): bool;
}
