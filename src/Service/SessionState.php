<?php

namespace TackTack\TwoFactor\Service;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Lecture/écriture des clés de session du paquet.
 *
 * Les deux valeurs sont liées à un uID : une valeur posée pour un autre utilisateur
 * (« Se connecter en tant que ») est ignorée.
 */
class SessionState
{
    public const VERIFIED_KEY = 'tacktack_2fa.verified';
    public const ENROLL_KEY = 'tacktack_2fa.enroll';
    public const PENDING_SINCE_KEY = 'tacktack_2fa.pending_since';
    public const REMEMBER_KEY = 'tacktack_2fa.remember';
    public const IMPERSONATION_KEY = 'tacktack_2fa.impersonation';
    public const SUDO_PENDING_KEY = 'tacktack_2fa.sudo_pending';

    /** @var SessionInterface */
    protected $session;

    public function __construct(SessionInterface $session)
    {
        $this->session = $session;
    }

    /**
     * @return array{uID:int, at:int}|null
     */
    public function getVerified(): ?array
    {
        $value = $this->session->get(self::VERIFIED_KEY);

        return is_array($value) ? $value : null;
    }

    public function markVerified(int $uID): void
    {
        $this->session->set(self::VERIFIED_KEY, ['uID' => $uID, 'at' => time()]);
    }

    public function clearVerified(): void
    {
        $this->session->remove(self::VERIFIED_KEY);
    }

    /**
     * Secret en cours d'enrôlement, gardé en session tant qu'il n'est pas confirmé
     * (aucune ligne à moitié enrôlée en base).
     */
    public function getPendingSecret(int $uID): ?string
    {
        $value = $this->session->get(self::ENROLL_KEY);
        if (!is_array($value) || (int) ($value['uID'] ?? 0) !== $uID || !is_string($value['secret'] ?? null)) {
            return null;
        }

        return $value['secret'];
    }

    public function setPendingSecret(int $uID, string $secret): void
    {
        $this->session->set(self::ENROLL_KEY, ['uID' => $uID, 'secret' => $secret, 'at' => time()]);
    }

    public function clearPendingSecret(): void
    {
        $this->session->remove(self::ENROLL_KEY);
    }

    /**
     * Début de l'étape 2FA (état « pending »), posé une seule fois par le middleware :
     * un simple rafraîchissement ne remet pas le délai de 5 minutes à zéro.
     * Un marqueur absent ou posé pour un autre uID compte comme expiré.
     */
    public function touchPendingSince(int $uID): void
    {
        $value = $this->session->get(self::PENDING_SINCE_KEY);
        if (is_array($value) && (int) ($value['uID'] ?? 0) === $uID) {
            return;
        }
        $this->session->set(self::PENDING_SINCE_KEY, ['uID' => $uID, 'at' => time()]);
    }

    public function getPendingSince(int $uID): ?int
    {
        $value = $this->session->get(self::PENDING_SINCE_KEY);
        if (!is_array($value) || (int) ($value['uID'] ?? 0) !== $uID || !is_int($value['at'] ?? null)) {
            return null;
        }

        return $value['at'];
    }

    public function clearPendingSince(): void
    {
        $this->session->remove(self::PENDING_SINCE_KEY);
    }

    /**
     * Type d'authentification du cookie « rester connecté » mis de côté pendant l'étape 2FA,
     * à reposer après un code valide.
     */
    public function getRememberHandle(int $uID): ?string
    {
        $value = $this->session->get(self::REMEMBER_KEY);
        if (!is_array($value) || (int) ($value['uID'] ?? 0) !== $uID || !is_string($value['handle'] ?? null)) {
            return null;
        }

        return $value['handle'];
    }

    public function setRememberHandle(int $uID, string $handle): void
    {
        $this->session->set(self::REMEMBER_KEY, ['uID' => $uID, 'handle' => $handle]);
    }

    public function clearRememberHandle(): void
    {
        $this->session->remove(self::REMEMBER_KEY);
    }

    /**
     * Nouvel identifiant de session, en conservant les données : à appeler quand le niveau
     * d'authentification change (code valide, enrôlement confirmé).
     */
    public function regenerate(): void
    {
        $this->session->migrate(true);
    }

    /**
     * Session ouverte par le super utilisateur via « Se connecter en tant que ». La
     * marque est liée à l'uID de la cible : une autre identité en session l'ignore.
     */
    public function setImpersonation(int $uID, int $origin): void
    {
        $this->session->set(self::IMPERSONATION_KEY, ['uID' => $uID, 'origin' => $origin]);
    }

    public function isImpersonating(int $uID): bool
    {
        $value = $this->session->get(self::IMPERSONATION_KEY);

        return is_array($value) && (int) ($value['uID'] ?? 0) === $uID && $uID > 0;
    }

    /**
     * Intention de « Se connecter en tant que », notée AVANT la requête : le cœur termine
     * l'action par exit (Controller::redirect), le middleware ne reprend donc jamais la main
     * après elle. Confirmée (ou jetée) par une requête suivante : voir peekSudoPending() puis clearSudoPending(), pilotés par SudoIntent::evaluate().
     */
    public function armSudo(int $origin, int $target): void
    {
        $this->session->set(self::SUDO_PENDING_KEY, ['origin' => $origin, 'target' => $target, 'at' => time()]);
    }

    /**
     * @return array{origin:int, target:int, at:int}|null
     */
    public function peekSudoPending(): ?array
    {
        $value = $this->session->get(self::SUDO_PENDING_KEY);
        if (!is_array($value) || !is_int($value['origin'] ?? null) || !is_int($value['target'] ?? null) || !is_int($value['at'] ?? null)) {
            return null;
        }

        return $value;
    }

    public function clearSudoPending(): void
    {
        $this->session->remove(self::SUDO_PENDING_KEY);
    }
}
