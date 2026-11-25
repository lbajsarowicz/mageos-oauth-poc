<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use League\OAuth2\Server\Exception\OAuthServerException;
use MageOS\OauthApi\Api\ResourceServerRegistryInterface;

/**
 * OAuth 2.1 rules league/oauth2-server leaves optional: PKCE for every client, S256 only, and exactly one
 * registered RFC 8707 resource per authorization request.
 */
class AuthorizeRequestGuard
{
    public const PARAMETERS = [
        'response_type',
        'client_id',
        'redirect_uri',
        'scope',
        'state',
        'code_challenge',
        'code_challenge_method',
        'resource',
    ];

    public function __construct(
        private readonly ResourceServerRegistryInterface $registry
    ) {
    }

    /**
     * @param array $query
     * @return string The resource URI the grant will be bound to
     * @throws OAuthServerException
     */
    public function assertValid(array $query): string
    {
        foreach (self::PARAMETERS as $parameter) {
            if (isset($query[$parameter]) && !is_string($query[$parameter])) {
                throw OAuthServerException::invalidRequest($parameter, 'The parameter must be given once.');
            }
        }
        if (($query['response_type'] ?? null) !== 'code') {
            throw new OAuthServerException('Only the code response type is supported.', 2, 'unsupported_response_type');
        }
        if (($query['code_challenge'] ?? '') === '') {
            throw OAuthServerException::invalidRequest('code_challenge', 'PKCE is required.');
        }
        if (($query['code_challenge_method'] ?? null) !== 'S256') {
            throw OAuthServerException::invalidRequest('code_challenge_method', 'Only S256 is supported.');
        }

        $resource = $query['resource'] ?? '';
        if ($resource === '' || $this->registry->getByUri($resource) === null) {
            throw new OAuthServerException(
                'The resource parameter is missing or not served here.',
                3,
                'invalid_target'
            );
        }

        return $resource;
    }

    /**
     * @param array $query
     * @return array<string, string>
     */
    public function filter(array $query): array
    {
        return array_filter(
            array_intersect_key($query, array_flip(self::PARAMETERS)),
            'is_string'
        );
    }
}
