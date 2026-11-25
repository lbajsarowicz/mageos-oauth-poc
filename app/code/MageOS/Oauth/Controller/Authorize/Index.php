<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller\Authorize;

use League\OAuth2\Server\Exception\OAuthServerException;
use Magento\Backend\Model\UrlInterface as BackendUrl;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Controller\Result\RedirectFactory;
use Magento\Framework\Controller\ResultInterface;
use MageOS\Oauth\Http\Psr7Bridge;
use MageOS\Oauth\Model\AuthorizeRequestGuard;
use MageOS\Oauth\Model\Config;
use MageOS\Oauth\Model\Consent\PendingAuthorizationStore;
use MageOS\Oauth\Model\ServerFactory;

/**
 * Authorization endpoint. Validates the request, keeps it for the consent screen and sends the browser to the admin,
 * where the resource owner logs in and decides.
 */
class Index implements HttpGetActionInterface
{
    public function __construct(
        private readonly HttpRequest $request,
        private readonly Config $config,
        private readonly AuthorizeRequestGuard $guard,
        private readonly ServerFactory $serverFactory,
        private readonly Psr7Bridge $bridge,
        private readonly PendingAuthorizationStore $pendingStore,
        private readonly RedirectFactory $redirectFactory,
        private readonly BackendUrl $backendUrl
    ) {
    }

    public function execute(): ResultInterface
    {
        if (!$this->config->isEnabled()) {
            return $this->bridge->json(404, ['error' => 'not_found']);
        }

        $query = $this->request->getQuery()->toArray();
        try {
            $this->guard->assertValid($query);
            $this->serverFactory->getAuthorizationServer()->validateAuthorizationRequest(
                $this->bridge->toServerRequest($this->request, $query)
            );
        } catch (OAuthServerException $e) {
            return $this->bridge->toResult($e->generateHttpResponse($this->bridge->createResponse()));
        }

        $this->pendingStore->save($query);

        return $this->redirectFactory->create()->setUrl(
            $this->backendUrl->getUrl('mageos_oauth/consent/index', ['_nosecret' => true])
        );
    }
}
