<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api;

use MageOS\OauthApi\Api\Data\AccessTokenInterface;
use MageOS\OauthApi\Api\Exception\InvalidTokenException;

/**
 * Validates a bearer token presented to a registered resource server.
 *
 * A token is accepted only when its signature and expiry are valid, it is not revoked, it was issued for the
 * given resource, and its principal is still active. Scopes whose ACL resource the principal no longer holds are
 * left out of the result.
 *
 * @api
 */
interface TokenValidatorInterface
{
    /**
     * @param string $token Raw bearer token, without the "Bearer " prefix
     * @param string $resourcePath Path of the resource server as registered, for example "/rest"
     * @throws InvalidTokenException
     */
    public function validate(string $token, string $resourcePath): AccessTokenInterface;
}
