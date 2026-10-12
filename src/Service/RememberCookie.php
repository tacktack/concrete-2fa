<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\User\PersistentAuthentication\CookieService;
use Concrete\Core\User\User;

/**
 * Cookie « rester connecté » pendant l'étape 2FA.
 *
 * Concrete pose ce cookie dès la vérification du mot de passe, avant toute étape 2FA. Tant
 * qu'il existe, il reconnecte l'utilisateur sans mot de passe ni code. Il est donc supprimé
 * dès que l'utilisateur est soumis à l'étape 2FA, et reposé seulement après un code valide.
 */
class RememberCookie
{
    protected $cookies;
    protected $session;

    public function __construct(CookieService $cookies, SessionState $session)
    {
        $this->cookies = $cookies;
        $this->session = $session;
    }

    /**
     * Supprime le cookie de cet utilisateur et mémorise en session de quoi le reposer. Sans
     * effet s'il n'y a pas de cookie, ou s'il appartient à un autre utilisateur (on ne touche
     * pas au cookie d'autrui).
     */
    public function suspend(int $uID): void
    {
        $cookie = $this->cookies->getCookie();
        if ($cookie === null || (int) $cookie->getUserID() !== $uID) {
            return;
        }
        $this->session->setRememberHandle($uID, (string) $cookie->getAuthenticationTypeHandle());
        $this->cookies->deleteCookie();
    }

    /**
     * Repose le cookie après un code valide (ou un enrôlement confirmé). À appeler une fois
     * la session vérifiée.
     */
    public function restore(User $user): void
    {
        $handle = $this->session->getRememberHandle((int) $user->getUserID());
        if ($handle === null) {
            return;
        }
        $this->session->clearRememberHandle();
        $user->setAuthTypeCookie($handle);
    }
}
