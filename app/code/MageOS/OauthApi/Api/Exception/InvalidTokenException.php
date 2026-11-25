<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api\Exception;

use Magento\Framework\Exception\AuthenticationException;

/**
 * @api
 */
class InvalidTokenException extends AuthenticationException
{
}
