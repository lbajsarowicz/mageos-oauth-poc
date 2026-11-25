<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Data;

use DateTimeImmutable;
use MageOS\OauthApi\Api\Data\AccessTokenInterface;

class AccessToken implements AccessTokenInterface
{
    /**
     * @param string[] $scopes
     */
    public function __construct(
        private readonly string $tokenId,
        private readonly string $clientId,
        private readonly string $principalType,
        private readonly string $principalId,
        private readonly array $scopes,
        private readonly string $resource,
        private readonly DateTimeImmutable $expiresAt
    ) {
    }

    public function getTokenId(): string
    {
        return $this->tokenId;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getPrincipalType(): string
    {
        return $this->principalType;
    }

    public function getPrincipalId(): string
    {
        return $this->principalId;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    public function getResource(): string
    {
        return $this->resource;
    }

    public function getExpiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }
}
