<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\Config\Repository\Repository;

/**
 * Lecture de la politique (docs/paquet-2fa.md §3.7) : les valeurs enregistrées au Dashboard
 * (dépôt « config/database ») l'emportent ; à défaut, config/policy.php.
 *
 * Le dépôt « config » n'est pas utilisable seul : il ne relit pas la base pour l'espace de
 * noms du paquet et renverrait toujours les valeurs par défaut du fichier. Les groupes sont
 * stockés en JSON : une liste vide ne laisserait aucune ligne en base, et la valeur par
 * défaut du fichier reprendrait le dessus.
 */
class PolicyConfig
{
    public const NS = 'tacktack_2fa::policy.';

    /** @var Repository */
    protected $defaults;

    /** @var Repository */
    protected $database;

    public function __construct(Repository $defaults, Repository $database)
    {
        $this->defaults = $defaults;
        $this->database = $database;
    }

    /**
     * @return int[]
     */
    public function groups(): array
    {
        $value = $this->database->get(self::NS . 'groups');
        if (is_string($value)) {
            $decoded = json_decode($value, true);
            $value = is_array($decoded) ? $decoded : null;
        }
        if (!is_array($value)) {
            $value = $this->defaults->get(self::NS . 'groups', []);
        }

        return array_values(array_unique(array_map('intval', (array) $value)));
    }

    public function graceDays(): int
    {
        $value = $this->database->get(self::NS . 'grace_days');
        if ($value === null || $value === '') {
            $value = $this->defaults->get(self::NS . 'grace_days', 7);
        }

        return max(0, (int) $value);
    }

    public function issuer(): ?string
    {
        $value = $this->database->get(self::NS . 'issuer');
        if ($value === null) {
            $value = $this->defaults->get(self::NS . 'issuer');
        }

        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }

    /**
     * @param int[] $groups
     */
    public function save(array $groups, int $graceDays, ?string $issuer): void
    {
        $this->database->save(self::NS . 'groups', json_encode(array_values(array_unique(array_map('intval', $groups)))));
        $this->database->save(self::NS . 'grace_days', $graceDays);
        $this->database->save(self::NS . 'issuer', $issuer === null ? '' : $issuer);
    }
}
