<?php

namespace TackTack\TwoFactor\Http;

/**
 * Destination de retour après l'étape 2FA : un chemin local uniquement.
 *
 * Une URI commençant par « // » (URL relative au protocole) ou « /\ » (les navigateurs
 * traitent « \ » comme « / ») sortirait du site : c'est une redirection ouverte.
 */
class SafeLocation
{
    public static function isSafe(string $uri): bool
    {
        if ($uri === '' || $uri[0] !== '/') {
            return false;
        }
        if (isset($uri[1]) && ($uri[1] === '/' || $uri[1] === '\\')) {
            return false;
        }

        // Aucun caractère de contrôle ni antislash : rien de légitime n'en contient.
        return !preg_match('/[\x00-\x1f\x7f\\\\]/', $uri);
    }
}
