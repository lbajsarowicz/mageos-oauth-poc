<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Repository;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use MageOS\Oauth\Model\Entity\RefreshToken;

class RefreshTokenRepository extends AbstractTokenRepository implements RefreshTokenRepositoryInterface
{
    public const TABLE = 'mageos_oauth_refresh_token';

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new RefreshToken();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $this->insertRow([
            'token_id' => $refreshTokenEntity->getIdentifier(),
            'access_token_id' => $refreshTokenEntity->getAccessToken()->getIdentifier(),
            'resource' => $this->resourceBinding->getBound(),
            'expires_at' => $this->formatDate($refreshTokenEntity->getExpiryDateTime()),
        ]);
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $this->markRevoked($tokenId);
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $row = $this->getRow($tokenId);
        if (!$this->isRowUsable($row)) {
            return true;
        }
        $this->resourceBinding->bindTo($row['resource']);

        return false;
    }

    protected function getTable(): string
    {
        return self::TABLE;
    }

    protected function getIdField(): string
    {
        return 'token_id';
    }
}
