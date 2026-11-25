<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller;

use Magento\Framework\App\ActionFactory;
use Magento\Framework\App\ActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\RouterInterface;
use MageOS\Oauth\Controller\Metadata\AuthorizationServer;
use MageOS\Oauth\Controller\Metadata\ProtectedResource;

/**
 * Routes the RFC 8414 and RFC 9728 well-known URIs, which do not fit the frontName/controller/action scheme.
 */
class Router implements RouterInterface
{
    private const AUTHORIZATION_SERVER = '.well-known/oauth-authorization-server';
    private const PROTECTED_RESOURCE = '.well-known/oauth-protected-resource';

    public function __construct(
        private readonly ActionFactory $actionFactory
    ) {
    }

    public function match(RequestInterface $request): ?ActionInterface
    {
        $path = trim((string)$request->getPathInfo(), '/');

        if ($path === self::AUTHORIZATION_SERVER) {
            return $this->route($request, 'authorizationServer', AuthorizationServer::class);
        }
        if ($path === self::PROTECTED_RESOURCE || str_starts_with($path, self::PROTECTED_RESOURCE . '/')) {
            $request->setParam(
                ProtectedResource::PARAM_RESOURCE_PATH,
                '/' . substr($path, strlen(self::PROTECTED_RESOURCE) + 1)
            );

            return $this->route($request, 'protectedResource', ProtectedResource::class);
        }

        return null;
    }

    private function route(RequestInterface $request, string $action, string $class): ActionInterface
    {
        $request->setModuleName('mageos_oauth')->setControllerName('metadata')->setActionName($action);

        return $this->actionFactory->create($class);
    }
}
