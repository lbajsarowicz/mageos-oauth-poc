<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\CryptoException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use MageOS\Oauth\Model\Repository\RefreshTokenRepository;

/**
 * RFC 7009 token revocation. Tokens that do not parse, fail verification or belong to another client are ignored,
 * as the RFC requires the endpoint to answer 200 for those.
 */
class TokenRevocation
{
    public function __construct(
        private readonly Config $config,
        private readonly ServerFactory $serverFactory,
        private readonly GrantRevoker $grantRevoker,
        private readonly RefreshTokenRepository $refreshTokenRepository
    ) {
    }

    public function revoke(string $token, string $clientId): void
    {
        $accessTokenId = $this->accessTokenIdFromJwt($token, $clientId)
            ?? $this->accessTokenIdFromRefreshToken($token, $clientId);
        if ($accessTokenId !== null) {
            $this->grantRevoker->revokeAccessTokenFamily($accessTokenId);
        }
    }

    private function accessTokenIdFromJwt(string $token, string $clientId): ?string
    {
        if (substr_count($token, '.') !== 2) {
            return null;
        }
        try {
            $jwt = (new Parser(new JoseEncoder()))->parse($token);
            $valid = $jwt instanceof UnencryptedToken && (new Validator())->validate(
                $jwt,
                new SignedWith(new Sha256(), InMemory::plainText($this->config->getPublicKey()))
            );
        } catch (\Throwable) {
            return null;
        }
        if (!$valid || !$jwt->isPermittedFor($clientId)) {
            return null;
        }
        $jti = $jwt->claims()->get('jti');

        return is_string($jti) ? $jti : null;
    }

    private function accessTokenIdFromRefreshToken(string $token, string $clientId): ?string
    {
        try {
            $payload = json_decode(
                Crypto::decrypt($token, $this->serverFactory->getEncryptionKey()),
                true,
                4,
                JSON_THROW_ON_ERROR
            );
        } catch (CryptoException|\JsonException|\TypeError) {
            return null;
        }
        if (!is_array($payload) || ($payload['client_id'] ?? null) !== $clientId
            || !is_string($payload['refresh_token_id'] ?? null)) {
            return null;
        }
        $row = $this->refreshTokenRepository->getRow($payload['refresh_token_id']);

        return $row['access_token_id'] ?? null;
    }
}
