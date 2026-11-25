<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Http;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Controller\Result\Raw;
use Magento\Framework\Controller\Result\RawFactory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Converts between Magento HTTP objects and the PSR-7 messages league/oauth2-server works with.
 */
class Psr7Bridge
{
    public function __construct(
        private readonly RawFactory $rawFactory,
        private readonly StreamFactory $streamFactory
    ) {
    }

    public function toServerRequest(HttpRequest $request, ?array $query = null): ServerRequestInterface
    {
        $headers = [];
        foreach ($request->getHeaders() as $header) {
            $headers[$header->getFieldName()] = $header->getFieldValue();
        }

        return new ServerRequest(
            $request->getServer()->toArray(),
            [],
            $request->getUriString(),
            $request->getMethod(),
            $this->streamFactory->createStream((string)$request->getContent()),
            $headers,
            [],
            $query ?? $request->getQuery()->toArray(),
            $request->getPost()->toArray()
        );
    }

    public function createResponse(): ResponseInterface
    {
        return new Response();
    }

    public function toResult(ResponseInterface $response): Raw
    {
        $result = $this->rawFactory->create();
        $result->setHttpResponseCode($response->getStatusCode());
        foreach ($response->getHeaders() as $name => $values) {
            $result->setHeader($name, implode(', ', $values), true);
        }
        $result->setHeader('Cache-Control', 'no-store', true);
        $result->setHeader('Pragma', 'no-cache', true);
        $result->setContents((string)$response->getBody());

        return $result;
    }

    public function json(int $status, array $payload): Raw
    {
        $result = $this->rawFactory->create();
        $result->setHttpResponseCode($status);
        $result->setHeader('Content-Type', 'application/json', true);
        $result->setHeader('Cache-Control', 'no-store', true);
        $result->setContents(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        return $result;
    }
}
