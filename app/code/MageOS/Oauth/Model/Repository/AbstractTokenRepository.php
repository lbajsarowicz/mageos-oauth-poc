<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Repository;

use DateTimeImmutable;
use DateTimeZone;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\DuplicateException;
use MageOS\Oauth\Model\ResourceBinding;

/**
 * Shared row access for codes and tokens. Revocation state is always read from the database, never from a cache.
 */
abstract class AbstractTokenRepository
{
    /**
     * @var array<string, array|false>
     */
    private array $rows = [];

    public function __construct(
        protected readonly ResourceConnection $resourceConnection,
        protected readonly ResourceBinding $resourceBinding
    ) {
    }

    abstract protected function getTable(): string;

    abstract protected function getIdField(): string;

    public function getRow(string $id): ?array
    {
        if (!isset($this->rows[$id])) {
            $connection = $this->resourceConnection->getConnection();
            $this->rows[$id] = $connection->fetchRow(
                $connection->select()
                    ->from($this->resourceConnection->getTableName($this->getTable()))
                    ->where($this->getIdField() . ' = ?', $id)
            ) ?: false;
        }

        return $this->rows[$id] ?: null;
    }

    protected function insertRow(array $data): void
    {
        try {
            $this->resourceConnection->getConnection()->insert(
                $this->resourceConnection->getTableName($this->getTable()),
                $data
            );
        } catch (DuplicateException) {
            throw UniqueTokenIdentifierConstraintViolationException::create();
        }
        unset($this->rows[$data[$this->getIdField()]]);
    }

    protected function markRevoked(string $id): void
    {
        $this->resourceConnection->getConnection()->update(
            $this->resourceConnection->getTableName($this->getTable()),
            ['revoked' => 1],
            [$this->getIdField() . ' = ?' => $id]
        );
        unset($this->rows[$id]);
    }

    protected function isRowUsable(?array $row): bool
    {
        return $row !== null && (int)$row['revoked'] === 0;
    }

    protected function formatDate(DateTimeImmutable $date): string
    {
        return $date->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }

    protected function parseDate(string $date): DateTimeImmutable
    {
        return DateTimeImmutable::createFromFormat('Y-m-d H:i:s', $date, new DateTimeZone('UTC'))
            ?: new DateTimeImmutable('@0');
    }

    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    protected function encodeScopes(array $scopes): string
    {
        return json_encode(
            array_values(array_map(static fn ($scope): string => $scope->getIdentifier(), $scopes)),
            JSON_THROW_ON_ERROR
        );
    }

}
