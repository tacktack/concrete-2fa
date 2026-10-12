<?php

namespace TackTack\TwoFactor\Service;

use DateTimeImmutable;

/**
 * Limitation des tentatives par utilisateur (docs/paquet-2fa.md §2 décision #9) :
 * 5 échecs → verrou de 15 min. La partie IP (20 échecs / 10 min → bannissement 1 h) est
 * portée par la catégorie IpAccessControlCategory créée à l'installation ; le contrôleur
 * y enregistre chaque échec via IpAccessControlService.
 *
 * Cette classe ne contient que la logique du compteur, pure, pour être testable.
 */
class Throttle
{
    public const MAX_ATTEMPTS = 5;
    public const LOCK_MINUTES = 15;

    /**
     * Nouvel état après un échec.
     *
     * @return array{attempts:int, lockedUntil:?DateTimeImmutable, locked:bool}
     */
    public function registerFailure(int $failedAttempts, ?DateTimeImmutable $now = null): array
    {
        $now = $now ?? new DateTimeImmutable();
        $attempts = $failedAttempts + 1;

        if ($attempts >= self::MAX_ATTEMPTS) {
            return [
                'attempts' => 0,
                'lockedUntil' => $now->modify('+' . self::LOCK_MINUTES . ' minutes'),
                'locked' => true,
            ];
        }

        return ['attempts' => $attempts, 'lockedUntil' => null, 'locked' => false];
    }

    public function isLocked(?DateTimeImmutable $lockedUntil, ?DateTimeImmutable $now = null): bool
    {
        return $lockedUntil !== null && $lockedUntil > ($now ?? new DateTimeImmutable());
    }
}
