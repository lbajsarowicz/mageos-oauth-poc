<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Repository;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use MageOS\Oauth\Model\Entity\AuthCode;

class AuthCodeRepository extends AbstractTokenRepository implements AuthCodeRepositoryInterface
{
    public const TABLE = 'mageos_oauth_auth_code';

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        $this->insertRow([
            'code_id' => $authCodeEntity->getIdentifier(),
            'client_id' => $authCodeEntity->getClient()->getIdentifier(),
            'principal' => (string)$authCodeEntity->getUserIdentifier(),
            'scopes' => $this->encodeScopes($authCodeEntity->getScopes()),
            'resource' => $this->resourceBinding->getBound(),
            'expires_at' => $this->formatDate($authCodeEntity->getExpiryDateTime()),
        ]);
    }

    public function revokeAuthCode(string $codeId): void
    {
        $this->markRevoked($codeId);
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $row = $this->getRow($codeId);
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
        return 'code_id';
    }
}
