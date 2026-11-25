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
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\Controller\ResultInterface;
use Magento\Framework\View\Result\PageFactory;
use MageOS\Oauth\Model\Consent\AuthorizationService;
use MageOS\Oauth\Model\Consent\PendingAuthorizationStore;
use MageOS\Oauth\Model\Principal\AdminAuthorizer;

/**
 * Consent screen. Reached from the authorization endpoint without an admin secret key, because the frontend cannot
 * generate one; it only displays the request, the decision is a form-key protected POST.
 */
class Index extends Action implements HttpGetActionInterface
{
    public const ADMIN_RESOURCE = 'MageOS_Oauth::authorize';

    public function __construct(
        Context $context,
        private readonly PendingAuthorizationStore $pendingStore,
        private readonly AuthorizationService $authorizationService,
        private readonly PageFactory $pageFactory
    ) {
        parent::__construct($context);
    }

    public function execute(): ResultInterface
    {
        $query = $this->pendingStore->load();
        if ($query === null) {
            $this->messageManager->addErrorMessage(__('There is no pending authorization request.'));

            return $this->resultRedirectFactory->create()->setPath('admin/dashboard');
        }

        try {
            $this->authorizationService->restore(
                $query,
                AdminAuthorizer::principalFor((int)$this->_auth->getUser()->getId())
            );
        } catch (OAuthServerException $e) {
            $this->pendingStore->clear();
            $this->messageManager->addErrorMessage(
                __('The authorization request is not valid: %1', $e->getHint() ?: $e->getMessage())
            );

            return $this->resultRedirectFactory->create()->setPath('admin/dashboard');
        }

        $page = $this->pageFactory->create();
        $page->getConfig()->getTitle()->prepend(__('Authorize Application'));

        return $page;
    }

    protected function _validateSecretKey()
    {
        return true;
    }
}
