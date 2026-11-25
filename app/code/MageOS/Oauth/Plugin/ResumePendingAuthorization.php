<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Plugin;

use Magento\Backend\Model\Url;
use MageOS\Oauth\Model\Consent\PendingAuthorizationStore;

/**
 * With admin secret keys on, a successful login redirects to the startup page instead of the requested URL. While an
 * authorization request is pending, the consent screen is the startup page, so the flow resumes after login.
 */
class ResumePendingAuthorization
{
    public function __construct(
        private readonly PendingAuthorizationStore $pendingStore
    ) {
    }

    /**
     * @param string|null $result
     */
    public function afterGetStartupPageUrl(Url $subject, $result)
    {
        return $this->pendingStore->hasPending() ? 'mageos_oauth/consent/index' : $result;
    }
}
