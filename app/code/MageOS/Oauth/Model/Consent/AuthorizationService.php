<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Consent;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use MageOS\Oauth\Model\AuthorizeRequestGuard;
use MageOS\Oauth\Model\Entity\Scope as ScopeEntity;
use MageOS\Oauth\Model\Entity\User;
use MageOS\Oauth\Model\ResourceBinding;
use MageOS\Oauth\Model\ServerFactory;
use MageOS\OauthApi\Api\PrincipalAuthorizerInterface;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Restores a pending authorization request, decides which requested scopes the principal can grant, and completes
 * the request as approved or denied.
 */
class AuthorizationService
{
    public function __construct(
        private readonly AuthorizeRequestGuard $guard,
        private readonly ServerFactory $serverFactory,
        private readonly ResourceServerRegistryInterface $registry,
        private readonly PrincipalAuthorizerInterface $principalAuthorizer,
        private readonly ResourceBinding $resourceBinding,
        private readonly PendingAuthorization $pending
    ) {
    }

    /**
     * @param array<string, string> $query
     * @throws OAuthServerException
     */
    public function restore(array $query, string $principal): PendingAuthorization
    {
        $resource = $this->guard->assertValid($query);
        $request = $this->serverFactory->getAuthorizationServer()->validateAuthorizationRequest(
            (new ServerRequest())->withQueryParams($query)
        );
        $resourceServer = $this->registry->getByUri($resource);

        $grantable = [];
        $refused = [];
        foreach ($request->getScopes() as $scope) {
            $definition = $resourceServer->getScopes()[$scope->getIdentifier()] ?? null;
            $acl = $definition?->getAclResource();
            if ($definition === null || ($acl !== null && !$this->principalAuthorizer->isAllowed($principal, $acl))) {
                $refused[] = $scope->getIdentifier();
                continue;
            }
            $grantable[] = $definition;
        }
        $this->pending->set($request, $resourceServer, $grantable, $refused);

        return $this->pending;
    }

    /**
     * @throws OAuthServerException
     */
    public function complete(PendingAuthorization $pending, string $principal, bool $approved): ResponseInterface
    {
        $request = $pending->getRequest();
        $request->setUser(new User($principal));
        $request->setScopes(array_map(
            static fn ($scope): ScopeEntity => new ScopeEntity($scope->getName()),
            $pending->getGrantable()
        ));
        $request->setAuthorizationApproved($approved && $pending->getGrantable() !== []);
        $this->resourceBinding->request(null);
        $this->resourceBinding->bindTo($this->registry->getUri($pending->getResourceServer()));

        try {
            return $this->serverFactory->getAuthorizationServer()->completeAuthorizationRequest(
                $request,
                new Response()
            );
        } catch (OAuthServerException $e) {
            return $e->generateHttpResponse(new Response());
        }
    }
}
