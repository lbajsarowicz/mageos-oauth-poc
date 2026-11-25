<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use Magento\Framework\App\ResourceConnection;
use MageOS\Oauth\Model\Repository\AccessTokenRepository;
use MageOS\Oauth\Model\Repository\RefreshTokenRepository;
use MageOS\OauthApi\Api\GrantRevokerInterface;

class GrantRevoker implements GrantRevokerInterface
{
    public function __construct(
        private readonly ResourceConnection $resourceConnection
    ) {
    }

    public function revokeForPrincipal(string $principal): int
    {
        return $this->revokeWhere('principal = ?', $principal);
    }

    public function revokeForClient(string $clientId): int
    {
        return $this->revokeWhere('client_id = ?', $clientId);
    }

    /**
     * Revokes the access token and every refresh token issued with it
     */
    public function revokeAccessTokenFamily(string $accessTokenId): int
    {
        return $this->revokeWhere('token_id = ?', $accessTokenId);
    }

    private function revokeWhere(string $condition, string $value): int
    {
        $connection = $this->resourceConnection->getConnection();
        $accessTable = $this->resourceConnection->getTableName(AccessTokenRepository::TABLE);
        $refreshTable = $this->resourceConnection->getTableName(RefreshTokenRepository::TABLE);

        $connection->beginTransaction();
        try {
            $refreshCount = $connection->update(
                $refreshTable,
                ['revoked' => 1],
                [
                    'revoked = ?' => 0,
                    'access_token_id IN (?)' => $connection->select()
                        ->from($accessTable, ['token_id'])
                        ->where($condition, $value),
                ]
            );
            $accessCount = $connection->update(
                $accessTable,
                ['revoked' => 1],
                ['revoked = ?' => 0, $condition => $value]
            );
            $connection->commit();
        } catch (\Throwable $e) {
            $connection->rollBack();
            throw $e;
        }

        return $accessCount + $refreshCount;
    }
}
