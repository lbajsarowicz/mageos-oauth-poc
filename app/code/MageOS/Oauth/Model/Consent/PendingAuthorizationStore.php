<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Consent;

use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Stdlib\Cookie\CookieMetadataFactory;
use Magento\Framework\Stdlib\CookieManagerInterface;
use MageOS\Oauth\Model\AuthorizeRequestGuard;

/**
 * Keeps the parameters of an authorization request across the admin login. The cookie holds no secret: the consent
 * screen re-validates every parameter, and approval needs a logged-in admin and a form key.
 */
class PendingAuthorizationStore
{
    public const COOKIE_NAME = 'mageos_oauth_authorize';

    private const LIFETIME = 600;

    public function __construct(
        private readonly CookieManagerInterface $cookieManager,
        private readonly CookieMetadataFactory $cookieMetadataFactory,
        private readonly AuthorizeRequestGuard $guard,
        private readonly HttpRequest $request
    ) {
    }

    /**
     * @param array $query
     */
    public function save(array $query): void
    {
        $this->cookieManager->setPublicCookie(
            self::COOKIE_NAME,
            http_build_query($this->guard->filter($query)),
            $this->cookieMetadataFactory->createPublicCookieMetadata()
                ->setDuration(self::LIFETIME)
                ->setPath('/')
                ->setHttpOnly(true)
                ->setSecure($this->request->isSecure())
                ->setSameSite('Lax')
        );
    }

    public function hasPending(): bool
    {
        return (string)$this->cookieManager->getCookie(self::COOKIE_NAME) !== '';
    }

    /**
     * @return array<string, string>|null
     */
    public function load(): ?array
    {
        $value = (string)$this->cookieManager->getCookie(self::COOKIE_NAME);
        if ($value === '') {
            return null;
        }
        parse_str($value, $query);

        return $this->guard->filter($query);
    }

    public function clear(): void
    {
        $this->cookieManager->deleteCookie(
            self::COOKIE_NAME,
            $this->cookieMetadataFactory->createCookieMetadata()->setPath('/')
        );
    }
}
