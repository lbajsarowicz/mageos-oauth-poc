<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api\Data;

/**
 * A validated access token and the authority it carries at the time of validation.
 *
 * @api
 */
interface AccessTokenInterface
{
    public function getTokenId(): string;

    public function getClientId(): string;

    /**
     * Principal type, for example "admin"
     */
    public function getPrincipalType(): string;

    public function getPrincipalId(): string;

    /**
     * @return string[]
     */
    public function getScopes(): array;

    public function hasScope(string $scope): bool;

    /**
     * Absolute URI of the resource the token is bound to
     */
    public function getResource(): string;

    public function getExpiresAt(): \DateTimeImmutable;
}
