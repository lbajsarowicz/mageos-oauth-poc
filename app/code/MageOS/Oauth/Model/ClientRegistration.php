<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use InvalidArgumentException;
use MageOS\Oauth\Model\Repository\ClientRepository;

/**
 * RFC 7591 dynamic client registration. A registered client gets no authority by itself: every grant still needs
 * an admin's approval on the consent screen.
 */
class ClientRegistration
{
    public const ERROR_REDIRECT_URI = 'invalid_redirect_uri';
    public const ERROR_METADATA = 'invalid_client_metadata';

    private const AUTH_METHODS = ['none', 'client_secret_post', 'client_secret_basic'];
    private const GRANT_TYPES = ['authorization_code', 'refresh_token'];
    private const MAX_REDIRECT_URIS = 10;

    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly RedirectUriPolicy $redirectUriPolicy
    ) {
    }

    /**
     * @param array $metadata Decoded registration request
     * @return array Registration response (RFC 7591 section 3.2.1)
     * @throws InvalidArgumentException with the RFC 7591 error code as message
     */
    public function register(array $metadata, string $registration = 'dynamic'): array
    {
        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || count($redirectUris) > self::MAX_REDIRECT_URIS
            || !array_is_list($redirectUris)) {
            throw new InvalidArgumentException(self::ERROR_REDIRECT_URI);
        }
        foreach ($redirectUris as $uri) {
            if (!is_string($uri) || !$this->redirectUriPolicy->isAllowed($uri)) {
                throw new InvalidArgumentException(self::ERROR_REDIRECT_URI);
            }
        }

        $name = $metadata['client_name'] ?? 'Unnamed client';
        if (!is_string($name) || $name === '' || mb_strlen($name) > 255) {
            throw new InvalidArgumentException(self::ERROR_METADATA);
        }
        $name = preg_replace('/[\x00-\x1f\x7f]/u', '', $name) ?? '';

        $authMethod = $metadata['token_endpoint_auth_method'] ?? 'none';
        if (!is_string($authMethod) || !in_array($authMethod, self::AUTH_METHODS, true)) {
            throw new InvalidArgumentException(self::ERROR_METADATA);
        }

        $grantTypes = $metadata['grant_types'] ?? ['authorization_code', 'refresh_token'];
        if (!is_array($grantTypes) || $grantTypes === []
            || array_diff($grantTypes, self::GRANT_TYPES) !== []
            || !in_array('authorization_code', $grantTypes, true)) {
            throw new InvalidArgumentException(self::ERROR_METADATA);
        }
        $grantTypes = array_values(array_unique($grantTypes));

        $responseTypes = $metadata['response_types'] ?? ['code'];
        if ($responseTypes !== ['code']) {
            throw new InvalidArgumentException(self::ERROR_METADATA);
        }

        $clientId = bin2hex(random_bytes(16));
        $secret = $authMethod === 'none' ? null : bin2hex(random_bytes(32));
        $this->clientRepository->create(
            $clientId,
            $name,
            $redirectUris,
            $grantTypes,
            $secret === null ? null : password_hash($secret, PASSWORD_DEFAULT),
            $registration
        );

        $response = [
            'client_id' => $clientId,
            'client_id_issued_at' => time(),
            'client_name' => $name,
            'redirect_uris' => $redirectUris,
            'grant_types' => $grantTypes,
            'response_types' => ['code'],
            'token_endpoint_auth_method' => $authMethod,
        ];
        if ($secret !== null) {
            $response['client_secret'] = $secret;
            $response['client_secret_expires_at'] = 0;
        }

        return $response;
    }
}
