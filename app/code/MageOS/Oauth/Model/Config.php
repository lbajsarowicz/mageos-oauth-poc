<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

use DateInterval;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\Exception\LocalizedException;
use Magento\Framework\UrlInterface;
use Magento\Store\Model\StoreManagerInterface;

/**
 * Settings of the authorization server. Signing and encryption keys live in env.php under "mageos_oauth".
 */
class Config
{
    public const DEPLOYMENT_CONFIG_PRIVATE_KEY = 'mageos_oauth/private_key';
    public const DEPLOYMENT_CONFIG_PUBLIC_KEY = 'mageos_oauth/public_key';
    public const DEPLOYMENT_CONFIG_ENCRYPTION_KEY = 'mageos_oauth/encryption_key';

    private const XML_PATH_ENABLED = 'mageos_oauth/general/enabled';
    private const XML_PATH_DYNAMIC_REGISTRATION = 'mageos_oauth/general/dynamic_client_registration';
    private const XML_PATH_ACCESS_TOKEN_LIFETIME = 'mageos_oauth/general/access_token_lifetime';
    private const XML_PATH_REFRESH_TOKEN_LIFETIME = 'mageos_oauth/general/refresh_token_lifetime';
    private const XML_PATH_AUTH_CODE_LIFETIME = 'mageos_oauth/general/auth_code_lifetime';

    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly DeploymentConfig $deploymentConfig,
        private readonly StoreManagerInterface $storeManager
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_PATH_ENABLED) && $this->hasKeys();
    }

    public function isDynamicRegistrationEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_PATH_DYNAMIC_REGISTRATION);
    }

    public function getAccessTokenLifetime(): DateInterval
    {
        return $this->seconds(self::XML_PATH_ACCESS_TOKEN_LIFETIME);
    }

    public function getRefreshTokenLifetime(): DateInterval
    {
        return $this->seconds(self::XML_PATH_REFRESH_TOKEN_LIFETIME);
    }

    public function getAuthCodeLifetime(): DateInterval
    {
        return $this->seconds(self::XML_PATH_AUTH_CODE_LIFETIME);
    }

    public function hasKeys(): bool
    {
        return (string)$this->deploymentConfig->get(self::DEPLOYMENT_CONFIG_PRIVATE_KEY) !== ''
            && (string)$this->deploymentConfig->get(self::DEPLOYMENT_CONFIG_PUBLIC_KEY) !== ''
            && (string)$this->deploymentConfig->get(self::DEPLOYMENT_CONFIG_ENCRYPTION_KEY) !== '';
    }

    public function getPrivateKey(): string
    {
        return $this->requireKey(self::DEPLOYMENT_CONFIG_PRIVATE_KEY);
    }

    public function getPublicKey(): string
    {
        return $this->requireKey(self::DEPLOYMENT_CONFIG_PUBLIC_KEY);
    }

    public function getEncryptionKey(): string
    {
        return $this->requireKey(self::DEPLOYMENT_CONFIG_ENCRYPTION_KEY);
    }

    /**
     * Issuer identifier (RFC 8414): the secure base URL of the default store view, without trailing slash
     */
    public function getIssuer(): string
    {
        return rtrim($this->storeManager->getDefaultStoreView()->getBaseUrl(UrlInterface::URL_TYPE_WEB, true), '/');
    }

    private function seconds(string $path): DateInterval
    {
        return new DateInterval('PT' . max(1, (int)$this->scopeConfig->getValue($path)) . 'S');
    }

    private function requireKey(string $path): string
    {
        $value = (string)$this->deploymentConfig->get($path);
        if ($value === '') {
            throw new LocalizedException(__('Run bin/magento mageos:oauth:keys:generate first.'));
        }

        return $value;
    }
}
