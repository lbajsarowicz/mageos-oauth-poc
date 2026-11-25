# MageOS_Oauth (proof of concept)

An OAuth 2.1 authorization server for Mage-OS, built on [league/oauth2-server](https://oauth2.thephpleague.com/) 9.x. It issues access tokens that other modules accept as their API credential. MCP is the first intended consumer, but this module knows nothing about MCP.

## Modules

| Module | Role |
|---|---|
| `MageOS_OauthApi` | Service contracts only: `TokenValidatorInterface`, `ResourceServerRegistryInterface`, `PrincipalAuthorizerInterface`, `GrantRevokerInterface`. Bridges depend on this module and nothing else. |
| `MageOS_Oauth` | The authorization server: endpoints, storage, consent screen, CLI. |
| `MageOS_OauthWebapi` | Example bridge: REST accepts OAuth access tokens through a `CompositeUserContext` entry, and the admin role's ACL applies. |

## What league/oauth2-server covers and what this module adds

The library handles the authorization code grant, refresh tokens with rotation, PKCE verification, JWT access tokens (RS256, lcobucci/jwt), encrypted codes and refresh tokens (defuse/php-encryption), and bearer validation.

This module adds the rest:

- OAuth 2.1 rules the library leaves optional: PKCE for every client, `S256` only, no implicit or password grant (`AuthorizeRequestGuard`).
- RFC 8707 resource indicators. Each grant is bound to one registered resource, and the binding is checked at code exchange, at refresh and on every validation (`ResourceBinding`).
- RFC 7591 dynamic client registration, with a redirect URI policy (https, loopback http, native app schemes).
- RFC 7009 revocation, RFC 8414 authorization server metadata and RFC 9728 protected resource metadata.
- Magento identity: admin users are the principals (`admin:<id>`). Scopes map to ACL resources. A role change or user deactivation takes effect on the next request, because `TokenValidator` reads revocation and principal state from the database every time.

## Flow

1. The client registers at `POST /oauth2/register` (or is created by an admin).
2. `GET /oauth2/authorize` validates the request, keeps its parameters in a 10-minute cookie, and redirects to the admin consent screen.
3. The admin logs in. With secret keys on, Magento sends every login to the startup page, so a plugin on `Backend\Model\Url::getStartupPageUrl()` points it at the consent screen while a request is pending.
4. The consent screen re-validates the request. It shows the client name as text and the redirect host, and it drops scopes the admin's role does not allow. Approval is a form-key POST.
5. The client exchanges the code at `POST /oauth2/token` with its PKCE verifier and gets a JWT access token plus a refresh token.
6. A bridge calls `TokenValidatorInterface::validate($token, '/rest')` and gets the principal and the scopes that are still allowed.

## Declaring a resource server from a bridge

```xml
<type name="MageOS\OauthApi\Api\ResourceServerRegistryInterface">
    <arguments>
        <argument name="resourceServers" xsi:type="array">
            <item name="mcp" xsi:type="array">
                <item name="path" xsi:type="string">/mcp</item>
                <item name="label" xsi:type="string">MCP server</item>
                <item name="scopes" xsi:type="array">
                    <item name="catalog:read" xsi:type="array">
                        <item name="description" xsi:type="string">Read products and categories</item>
                        <item name="acl_resource" xsi:type="string">Magento_Catalog::products</item>
                    </item>
                </item>
            </item>
        </argument>
    </arguments>
</type>
```

The core module then serves `/.well-known/oauth-protected-resource/mcp` and lists the scopes in its own metadata.

## Setup

```bash
bin/magento setup:upgrade
bin/magento mageos:oauth:keys:generate        # RSA 3072 key pair + encryption key into env.php
bin/magento mageos:oauth:revoke --principal=admin:5
bin/magento mageos:oauth:revoke --client=<client_id>
```

The admin role needs `System > Authorize OAuth Clients` (`MageOS_Oauth::authorize`) to approve a client.

## Not in the proof of concept

- Identity providers other than the admin session (Google OIDC, customers). `PrincipalAuthorizerInterface` already dispatches by principal type, but the authorize step still assumes an admin login.
- An admin grid for clients and grants. Revocation is CLI-only for now.
- Cron cleanup of expired codes and tokens. Rate limiting on `/oauth2/register` and `/oauth2/token`.
- Multi-domain setups. The issuer is the default store view's secure base URL, and the pending-request cookie only works when the admin shares the storefront host.
- Token introspection (RFC 7662) for resource servers outside Magento. Resource binding lives in the database row, not in the JWT `aud` claim (league sets that to the client ID).
- A dedicated `oauth_resource_servers.xml` file instead of the di.xml argument.
