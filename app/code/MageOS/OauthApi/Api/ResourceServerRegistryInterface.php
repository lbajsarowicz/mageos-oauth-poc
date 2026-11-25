<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\OauthApi\Api;

use MageOS\OauthApi\Api\Data\ResourceServerInterface;
use MageOS\OauthApi\Api\Data\ScopeInterface;

/**
 * Resource servers and their scopes, declared by bridge modules through the "resourceServers" di.xml argument
 * of this interface:
 *
 *     <type name="MageOS\OauthApi\Api\ResourceServerRegistryInterface">
 *         <arguments>
 *             <argument name="resourceServers" xsi:type="array">
 *                 <item name="rest" xsi:type="array">
 *                     <item name="path" xsi:type="string">/rest</item>
 *                     <item name="label" xsi:type="string">REST API</item>
 *                     <item name="scopes" xsi:type="array">
 *                         <item name="webapi" xsi:type="array">
 *                             <item name="description" xsi:type="string">Call the REST API as you</item>
 *                             <item name="acl_resource" xsi:type="string">Magento_Backend::admin</item>
 *                         </item>
 *                     </item>
 *                 </item>
 *             </argument>
 *         </arguments>
 *     </type>
 *
 * @api
 */
interface ResourceServerRegistryInterface
{
    /**
     * @return ResourceServerInterface[]
     */
    public function getAll(): array;

    public function getByPath(string $path): ?ResourceServerInterface;

    public function getByUri(string $uri): ?ResourceServerInterface;

    /**
     * Absolute URI of the resource server, used as token audience and RFC 8707 "resource" value
     */
    public function getUri(ResourceServerInterface $resourceServer): string;

    public function getScope(string $name): ?ScopeInterface;
}
