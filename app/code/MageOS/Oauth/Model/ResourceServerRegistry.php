<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use MageOS\Oauth\Model\Data\ResourceServer;
use MageOS\Oauth\Model\Data\Scope;
use MageOS\OauthApi\Api\Data\ResourceServerInterface;
use MageOS\OauthApi\Api\Data\ScopeInterface;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;

class ResourceServerRegistry implements ResourceServerRegistryInterface
{
    /**
     * @var ResourceServerInterface[]|null keyed by path
     */
    private ?array $servers = null;

    /**
     * @param array<string, array> $resourceServers Keyed by name; path, label, scopes
     */
    public function __construct(
        private readonly Config $config,
        private readonly array $resourceServers = []
    ) {
    }

    public function getAll(): array
    {
        return array_values($this->servers());
    }

    public function getByPath(string $path): ?ResourceServerInterface
    {
        return $this->servers()['/' . trim($path, '/')] ?? null;
    }

    public function getByUri(string $uri): ?ResourceServerInterface
    {
        $issuer = $this->config->getIssuer();
        if (!str_starts_with($uri, $issuer . '/')) {
            return null;
        }

        return $this->getByPath(substr($uri, strlen($issuer)));
    }

    public function getUri(ResourceServerInterface $resourceServer): string
    {
        return $this->config->getIssuer() . $resourceServer->getPath();
    }

    public function getScope(string $name): ?ScopeInterface
    {
        foreach ($this->servers() as $server) {
            if (isset($server->getScopes()[$name])) {
                return $server->getScopes()[$name];
            }
        }

        return null;
    }

    /**
     * @return ResourceServerInterface[]
     */
    private function servers(): array
    {
        if ($this->servers !== null) {
            return $this->servers;
        }

        $this->servers = [];
        foreach ($this->resourceServers as $name => $definition) {
            $path = '/' . trim((string)($definition['path'] ?? ''), '/');
            $scopes = [];
            foreach ($definition['scopes'] ?? [] as $scopeName => $scope) {
                $acl = (string)($scope['acl_resource'] ?? '');
                $scopes[$scopeName] = new Scope(
                    (string)$scopeName,
                    (string)($scope['description'] ?? $scopeName),
                    $acl === '' ? null : $acl
                );
            }
            $this->servers[$path] = new ResourceServer($path, (string)($definition['label'] ?? $name), $scopes);
        }

        return $this->servers;
    }
}
