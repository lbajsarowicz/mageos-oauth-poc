<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Repository;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use MageOS\Oauth\Model\Entity\AccessToken;

class AccessTokenRepository extends AbstractTokenRepository implements AccessTokenRepositoryInterface
{
    public const TABLE = 'mageos_oauth_access_token';

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null
    ): AccessTokenEntityInterface {
        $token = new AccessToken();
        $token->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }
        if ($userIdentifier !== null) {
            $token->setUserIdentifier($userIdentifier);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->insertRow([
            'token_id' => $accessTokenEntity->getIdentifier(),
            'client_id' => $accessTokenEntity->getClient()->getIdentifier(),
            'principal' => (string)$accessTokenEntity->getUserIdentifier(),
            'scopes' => $this->encodeScopes($accessTokenEntity->getScopes()),
            'resource' => $this->resourceBinding->getBound(),
            'expires_at' => $this->formatDate($accessTokenEntity->getExpiryDateTime()),
        ]);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->markRevoked($tokenId);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return !$this->isRowUsable($this->getRow($tokenId));
    }

    public function getExpiresAt(array $row): \DateTimeImmutable
    {
        return $this->parseDate($row['expires_at']);
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
