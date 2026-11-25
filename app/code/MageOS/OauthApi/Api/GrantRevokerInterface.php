<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api;

/**
 * Revokes issued tokens. Revocation takes effect on the next request; no cache sits in front of it.
 *
 * @api
 */
interface GrantRevokerInterface
{
    /**
     * @return int Number of access and refresh tokens revoked
     */
    public function revokeForPrincipal(string $principal): int;

    /**
     * @return int Number of access and refresh tokens revoked
     */
    public function revokeForClient(string $clientId): int;
}
