<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use MageOS\Oauth\Model\Data\AccessToken;
use MageOS\Oauth\Model\Repository\AccessTokenRepository;
use MageOS\OauthApi\Api\Data\AccessTokenInterface;
use MageOS\OauthApi\Api\Exception\InvalidTokenException;
use MageOS\OauthApi\Api\PrincipalAuthorizerInterface;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;
use MageOS\OauthApi\Api\TokenValidatorInterface;

class TokenValidator implements TokenValidatorInterface
{
    public function __construct(
        private readonly Config $config,
        private readonly ServerFactory $serverFactory,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ResourceServerRegistryInterface $registry,
        private readonly PrincipalAuthorizerInterface $principalAuthorizer
    ) {
    }

    public function validate(string $token, string $resourcePath): AccessTokenInterface
    {
        $resourceServer = $this->registry->getByPath($resourcePath);
        if ($resourceServer === null || !$this->config->isEnabled()) {
            throw new InvalidTokenException(__('The access token is not valid for this resource.'));
        }

        try {
            $request = $this->serverFactory->getResourceServer()->validateAuthenticatedRequest(
                (new ServerRequest())->withHeader('Authorization', 'Bearer ' . $token)
            );
        } catch (OAuthServerException $e) {
            throw new InvalidTokenException(__('The access token is not valid.'), $e);
        }

        $row = $this->accessTokenRepository->getRow((string)$request->getAttribute('oauth_access_token_id'));
        if ($row === null || $row['resource'] !== $this->registry->getUri($resourceServer)) {
            throw new InvalidTokenException(__('The access token is not valid for this resource.'));
        }

        $principal = $row['principal'];
        if (!$this->principalAuthorizer->isActive($principal)) {
            throw new InvalidTokenException(__('The resource owner of this token is not active.'));
        }

        $scopes = [];
        foreach (json_decode($row['scopes'], true, 4, JSON_THROW_ON_ERROR) as $scope) {
            $definition = $resourceServer->getScopes()[$scope] ?? null;
            if ($definition === null) {
                continue;
            }
            $acl = $definition->getAclResource();
            if ($acl === null || $this->principalAuthorizer->isAllowed($principal, $acl)) {
                $scopes[] = $scope;
            }
        }

        [$principalType, $principalId] = explode(':', $principal, 2) + [1 => ''];

        return new AccessToken(
            $row['token_id'],
            $row['client_id'],
            $principalType,
            $principalId,
            $scopes,
            $row['resource'],
            $this->accessTokenRepository->getExpiresAt($row)
        );
    }
}
