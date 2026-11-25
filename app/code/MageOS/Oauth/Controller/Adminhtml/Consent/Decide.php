<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Controller\Adminhtml\Consent;

use League\OAuth2\Server\Exception\OAuthServerException;
use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\ResultInterface;
use MageOS\Oauth\Model\Consent\AuthorizationService;
use MageOS\Oauth\Model\Consent\PendingAuthorizationStore;
use MageOS\Oauth\Model\Principal\AdminAuthorizer;

/**
 * Records the admin's decision and sends the browser back to the client's registered redirect URI.
 */
class Decide extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'MageOS_Oauth::authorize';

    public function __construct(
        Context $context,
        private readonly PendingAuthorizationStore $pendingStore,
        private readonly AuthorizationService $authorizationService
    ) {
        parent::__construct($context);
    }

    public function execute(): ResultInterface
    {
        $query = $this->pendingStore->load();
        $this->pendingStore->clear();
        if ($query === null) {
            $this->messageManager->addErrorMessage(__('There is no pending authorization request.'));

            return $this->resultRedirectFactory->create()->setPath('admin/dashboard');
        }

        $principal = AdminAuthorizer::principalFor((int)$this->_auth->getUser()->getId());
        try {
            $pending = $this->authorizationService->restore($query, $principal);
        } catch (OAuthServerException $e) {
            $this->messageManager->addErrorMessage(
                __('The authorization request is not valid: %1', $e->getHint() ?: $e->getMessage())
            );

            return $this->resultRedirectFactory->create()->setPath('admin/dashboard');
        }

        $response = $this->authorizationService->complete(
            $pending,
            $principal,
            $this->getRequest()->getPost('decision') === 'approve'
        );

        $location = $response->getHeaderLine('Location');
        if ($location === '') {
            $this->messageManager->addErrorMessage(__('The authorization request could not be completed.'));

            return $this->resultRedirectFactory->create()->setPath('admin/dashboard');
        }

        return $this->resultRedirectFactory->create()->setUrl($location);
    }
}
