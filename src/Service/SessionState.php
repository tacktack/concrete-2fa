<?php

namespace TackTack\TwoFactor\Service;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * Lecture/écriture des clés de session du paquet (docs/paquet-2fa.md §3.2, §3.5).
 *
 * Les deux valeurs sont liées à un uID : une valeur posée pour un autre utilisateur
 * (« Se connecter en tant que ») est ignorée.
 */
class SessionState
{
    public const VERIFIED_KEY = 'tacktack_2fa.verified';
    public const ENROLL_KEY = 'tacktack_2fa.enroll';
    public const PENDING_SINCE_KEY = 'tacktack_2fa.pending_since';

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
     * un simple rafraîchissement ne remet pas le délai de 5 minutes à zéro (§3.4).
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
}
