<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Magento\Framework\App\ResourceConnection;
use MageOS\Oauth\Model\Entity\Client;

class ClientRepository implements ClientRepositoryInterface
{
    public const TABLE = 'mageos_oauth_client';

    /**
     * @var array<string, array|false>
     */
    private array $rows = [];

    public function __construct(
        private readonly ResourceConnection $resourceConnection
    ) {
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $row = $this->getRow($clientIdentifier);
        if ($row === null) {
            return null;
        }

        return new Client(
            $row['client_id'],
            $row['client_name'],
            json_decode($row['redirect_uris'], true, 4, JSON_THROW_ON_ERROR),
            $row['secret_hash'] !== null,
            explode(' ', $row['grant_types'])
        );
    }

    public function validateClient(string $clientIdentifier, ?string $clientSecret, ?string $grantType): bool
    {
        $row = $this->getRow($clientIdentifier);
        if ($row === null) {
            return false;
        }
        if ($grantType !== null && !in_array($grantType, explode(' ', $row['grant_types']), true)) {
            return false;
        }
        if ($row['secret_hash'] === null) {
            return true;
        }

        return $clientSecret !== null && password_verify($clientSecret, $row['secret_hash']);
    }

    /**
     * @param string[] $redirectUris
     * @param string[] $grantTypes
     */
    public function create(
        string $clientId,
        string $name,
        array $redirectUris,
        array $grantTypes,
        ?string $secretHash,
        string $registration
    ): void {
        $this->resourceConnection->getConnection()->insert(
            $this->resourceConnection->getTableName(self::TABLE),
            [
                'client_id' => $clientId,
                'client_name' => $name,
                'redirect_uris' => json_encode(
                    array_values($redirectUris),
                    JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES
                ),
                'grant_types' => implode(' ', $grantTypes),
                'secret_hash' => $secretHash,
                'registration' => $registration,
            ]
        );
        unset($this->rows[$clientId]);
    }

    private function getRow(string $clientId): ?array
    {
        if (!isset($this->rows[$clientId])) {
            $connection = $this->resourceConnection->getConnection();
            $this->rows[$clientId] = $connection->fetchRow(
                $connection->select()
                    ->from($this->resourceConnection->getTableName(self::TABLE))
                    ->where('client_id = ?', $clientId)
            ) ?: false;
        }

        return $this->rows[$clientId] ?: null;
    }
}
