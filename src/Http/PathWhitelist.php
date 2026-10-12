<?php

namespace TackTack\TwoFactor\Http;

/**
 * Liste blanche du middleware, sans dépendance à Concrete pour rester testable.
 */
class PathWhitelist
{
    /**
     * Liste blanche, comparée sur le chemin décodé une seule fois. Un chemin
     * suspect (« .. », « // », un « % » restant, un caractère de contrôle) n'est jamais en
     * liste blanche. Le décodage est nécessaire : le jeton CSRF du lien de déconnexion
     * contient « : », transmis en « %3A ».
     */
    public static function matches(string $path): bool
    {
        $path = rawurldecode($path);
        if ($path === '' || $path[0] !== '/'
            || strpos($path, '..') !== false || strpos($path, '//') !== false || strpos($path, '%') !== false
            || preg_match('/[\x00-\x1f\x7f\\\\]/', $path)) {
            return false;
        }
        if (strncmp($path, '/index.php', 10) === 0) {
            $path = substr($path, 10);
            if ($path === '' || $path[0] !== '/') {
                return false;
            }
        }
        $path = rtrim($path, '/');

        // « /ccm/2fa » + frontière : « /ccm/2faX » n'y est pas.
        if ($path === '/ccm/2fa' || strncmp($path, '/ccm/2fa/', 9) === 0) {
            return true;
        }

        return $path === '/login/logout'
            || $path === '/login/logout_complete'
            || strncmp($path, '/login/logout/', 14) === 0
            || strncmp($path, '/login/do_logout/', 17) === 0;
    }
}
