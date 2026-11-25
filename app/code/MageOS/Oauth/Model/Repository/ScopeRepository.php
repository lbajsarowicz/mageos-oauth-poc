<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Repository;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use MageOS\Oauth\Model\Entity\Scope;
use MageOS\Oauth\Model\ResourceBinding;
use MageOS\OauthApi\Api\PrincipalAuthorizerInterface;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;

/**
 * Scopes come from the resource server registry. At every token issue (code exchange and refresh) the scopes are
 * narrowed to the bound resource server and to what the principal's role still allows.
 */
class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(
        private readonly ResourceServerRegistryInterface $registry,
        private readonly PrincipalAuthorizerInterface $principalAuthorizer,
        private readonly ResourceBinding $resourceBinding
    ) {
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return $this->registry->getScope($identifier) !== null ? new Scope($identifier) : null;
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null
    ): array {
        if ($userIdentifier === null || !$this->principalAuthorizer->isActive($userIdentifier)) {
            throw OAuthServerException::invalidGrant('The resource owner is not active.');
        }
        $resourceServer = $this->registry->getByUri($this->resourceBinding->getBound());
        if ($resourceServer === null) {
            throw OAuthServerException::invalidGrant('The resource of this grant is no longer registered.');
        }

        $granted = [];
        foreach ($scopes as $scope) {
            $definition = $resourceServer->getScopes()[$scope->getIdentifier()] ?? null;
            if ($definition === null) {
                continue;
            }
            $acl = $definition->getAclResource();
            if ($acl !== null && !$this->principalAuthorizer->isAllowed($userIdentifier, $acl)) {
                continue;
            }
            $granted[] = $scope;
        }
        if ($granted === []) {
            throw OAuthServerException::invalidGrant('None of the granted scopes is still allowed.');
        }

        return $granted;
    }
}
