<?php

namespace TackTack\TwoFactor\Service;

use DateTimeImmutable;

/**
 * Calcule l'état 2FA d'un utilisateur.
 *
 * Fonction pure : toutes les données nécessaires sont passées en arguments, pour que les
 * cinq états soient testables sans Concrete. Les appelants (middleware, contrôleurs)
 * collectent les entrées.
 */
class PolicyResolver
{
    public const NOT_REQUIRED = 'not_required';
    public const VERIFIED = 'verified';
    public const PENDING = 'pending';
    public const GRACE = 'grace';
    public const ENROLL_REQUIRED = 'enroll_required';

    /**
     * @param int                    $uID
     * @param bool                   $enrolled              secret confirmé (confirmedAt non null)
     * @param bool                   $concerned             groupe obligatoire, super utilisateur (uID 1)
     *                                                      ou enrôlement volontaire déjà fait
     * @param DateTimeImmutable|null $enforcementStartedAt  début du délai de grâce, null si jamais posé
     * @param int                    $graceDays
     * @param array|null             $sessionMarker         valeur de tacktack_2fa.verified en session
     */
    public function resolve(
        int $uID,
        bool $enrolled,
        bool $concerned,
        ?DateTimeImmutable $enforcementStartedAt,
        int $graceDays,
        ?array $sessionMarker,
        ?DateTimeImmutable $now = null
    ): string {
        $now = $now ?? new DateTimeImmutable();

        if (!$concerned && !$enrolled) {
            return self::NOT_REQUIRED;
        }

        // Un marqueur posé pour un autre uID vaut « non vérifié » : c'est ce qui rend
        // « Se connecter en tant que » fermé par construction.
        if ($enrolled && is_array($sessionMarker) && (int) ($sessionMarker['uID'] ?? 0) === $uID) {
            return self::VERIFIED;
        }

        if ($enrolled) {
            return self::PENDING;
        }

        // Concerné, non enrôlé. Pas de début de grâce enregistré = détecté à l'instant :
        // la grâce démarre maintenant (l'appelant persiste enforcementStartedAt).
        if ($enforcementStartedAt === null) {
            return $graceDays > 0 ? self::GRACE : self::ENROLL_REQUIRED;
        }

        $deadline = $enforcementStartedAt->modify('+' . max(0, $graceDays) . ' days');

        return $now < $deadline ? self::GRACE : self::ENROLL_REQUIRED;
    }
}
