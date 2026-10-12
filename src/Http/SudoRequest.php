<?php

namespace TackTack\TwoFactor\Http;

/**
 * Décision pure de l'exemption « Se connecter en tant que » du super utilisateur
 * (docs/paquet-2fa.md §2 décision #16, §3.3.1), sans dépendance à Concrete pour rester testable.
 */
class SudoRequest
{
    /**
     * @return int|null l'uID visé si le chemin est exactement l'action « sudo » du Dashboard
     */
    public static function targetFromPath(string $path): ?int
    {
        // Un seul décodage ; un chemin suspect n'est jamais reconnu (même règle que PathWhitelist).
        $path = rawurldecode($path);
        if ($path === '' || $path[0] !== '/'
            || strpos($path, '..') !== false || strpos($path, '//') !== false || strpos($path, '%') !== false
            || preg_match('/[\x00-\x1f\x7f\\\\]/', $path)) {
            return null;
        }
        if (strncmp($path, '/index.php', 10) === 0) {
            $path = substr($path, 10);
        }
        $path = rtrim($path, '/');

        if (!preg_match('#^/dashboard/users/search/update_status/sudo/([0-9]{1,10})$#', $path, $m)) {
            return null;
        }

        return (int) $m[1];
    }

    /**
     * Les trois conditions du §3.3.1, toutes nécessaires :
     *  1. la requête visait l'action « sudo » pour l'uID $target ;
     *  2. avant elle, la session était celle du super utilisateur, déjà vérifiée ;
     *  3. après elle, la session est devenue celle de $target (un autre utilisateur).
     */
    public static function isExemptSignIn(int $superID, int $before, bool $beforeVerified, int $after, ?int $target): bool
    {
        return $target !== null
            && $before === $superID
            && $beforeVerified
            && $after > 0
            && $after !== $before
            && $after === $target;
    }
}
