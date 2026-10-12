<?php

namespace TackTack\TwoFactor\Http;

/**
 * Cycle de vie de l'intention « Se connecter en tant que », sans
 * dépendance à Concrete pour rester testable.
 *
 * Le cœur termine l'action sudo par exit : le middleware note l'intention AVANT l'action, puis la
 * confirme à la requête suivante. Pour qu'elle ne puisse pas être détournée :
 *  - elle n'est notée que si la requête est un POST portant le jeton CSRF valide du cœur, émis
 *    pour le super utilisateur vérifié (le cœur exécutera alors réellement l'action) ;
 *  - elle expire vite (30 s : le navigateur enchaîne sur la redirection du cœur) ;
 *  - elle n'est honorée que si la session appartient maintenant à la cible demandée.
 */
class SudoIntent
{
    public const TTL = 30;

    public const NONE = 'none';
    /** Intention périmée, ou session d'un autre utilisateur que la cible : à effacer. */
    public const CLEAR = 'clear';
    /** La session est encore celle de l'origine : le basculement n'a pas (encore) eu lieu. */
    public const KEEP = 'keep';
    /** La session est devenue la cible demandée : exemption accordée, intention à effacer. */
    public const GRANT = 'grant';

    /**
     * Doit-on noter l'intention pour cette requête ?
     *
     * @param int|null $target    uID visé par le chemin (SudoRequest::targetFromPath), null si ce n'est pas l'action sudo
     * @param bool     $verified  la session du super utilisateur est « verified »
     * @param bool     $tokenValid jeton CSRF du cœur valide pour cette session
     */
    public static function shouldArm(string $method, ?int $target, int $uID, int $superID, bool $verified, bool $tokenValid): bool
    {
        return strtoupper($method) === 'POST'
            && $target !== null
            && $uID === $superID
            && $verified
            && $tokenValid;
    }

    /**
     * Décision à la requête courante, pour la session de l'utilisateur $uID.
     */
    public static function evaluate(?array $intent, int $uID, int $now, int $superID): string
    {
        if ($intent === null) {
            return self::NONE;
        }
        if (!SudoRequest::isFresh($intent['at'], $now, self::TTL)) {
            return self::CLEAR;
        }
        if ($uID === $intent['origin']) {
            return self::KEEP;
        }

        return SudoRequest::isExemptSignIn($superID, $intent['origin'], $uID, $intent['target'])
            ? self::GRANT
            : self::CLEAR;
    }
}
