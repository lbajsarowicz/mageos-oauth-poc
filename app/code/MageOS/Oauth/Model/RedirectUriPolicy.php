<?php
/**
 * Copyright 2026 Mage-OS
 * All Rights Reserved.
 */
declare(strict_types=1);

namespace MageOS\Oauth\Model;

/**
 * Redirect URIs a dynamically registered client may use: https, http on a loopback host (RFC 8252 section 7.3),
 * or a private-use scheme of a native app (RFC 8252 section 7.1). No fragments, no credentials.
 */
class RedirectUriPolicy
{
    private const FORBIDDEN_SCHEMES = ['javascript', 'data', 'file', 'vbscript', 'blob', 'about', 'ftp', 'ws', 'wss'];

    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

    public function isAllowed(string $uri): bool
    {
        if ($uri === '' || strlen($uri) > 2000 || preg_match('/[\x00-\x20\x7f]/', $uri)) {
            return false;
        }
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme']) || isset($parts['fragment'])
            || isset($parts['user']) || isset($parts['pass'])) {
            return false;
        }
        $scheme = strtolower($parts['scheme']);

        if ($scheme === 'https') {
            return isset($parts['host']) && $parts['host'] !== '';
        }
        if ($scheme === 'http') {
            return isset($parts['host']) && in_array(strtolower($parts['host']), self::LOOPBACK_HOSTS, true);
        }

        return preg_match('/^[a-z][a-z0-9+.\-]*$/', $scheme) === 1
            && !in_array($scheme, self::FORBIDDEN_SCHEMES, true);
    }
}
