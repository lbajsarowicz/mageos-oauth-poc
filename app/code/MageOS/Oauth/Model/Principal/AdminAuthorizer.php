<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model\Principal;

use Magento\Framework\Acl\Builder as AclBuilder;
use Magento\User\Model\ResourceModel\User as UserResource;
use Magento\User\Model\User;
use Magento\User\Model\UserFactory;
use MageOS\OauthApi\Api\PrincipalAuthorizerInterface;

/**
 * Admin users as principals ("admin:<user_id>"), checked against the same ACL the admin session uses.
 */
class AdminAuthorizer implements PrincipalAuthorizerInterface
{
    public const TYPE = 'admin';

    /**
     * @var array<int, User|false>
     */
    private array $users = [];

    public function __construct(
        private readonly UserFactory $userFactory,
        private readonly UserResource $userResource,
        private readonly AclBuilder $aclBuilder
    ) {
    }

    public static function principalFor(int $userId): string
    {
        return self::TYPE . ':' . $userId;
    }

    public function isActive(string $principal): bool
    {
        $user = $this->getUser($principal);
        if ($user === null || (int)$user->getIsActive() !== 1) {
            return false;
        }
        $lockExpires = $user->getData('lock_expires');

        return $lockExpires === null || strtotime((string)$lockExpires) < time();
    }

    public function isAllowed(string $principal, string $aclResource): bool
    {
        if (!$this->isActive($principal)) {
            return false;
        }
        try {
            return $this->aclBuilder->getAcl()->isAllowed($this->getUser($principal)->getAclRole(), $aclResource);
        } catch (\Exception) {
            return false;
        }
    }

    private function getUser(string $principal): ?User
    {
        [$type, $id] = explode(':', $principal, 2) + [1 => ''];
        if ($type !== self::TYPE || !ctype_digit($id)) {
            return null;
        }
        $userId = (int)$id;
        if (!isset($this->users[$userId])) {
            $user = $this->userFactory->create();
            $this->userResource->load($user, $userId);
            $this->users[$userId] = $user->getId() ? $user : false;
        }

        return $this->users[$userId] ?: null;
    }
}
