<?php

namespace TackTack\TwoFactor\Service;

/**
 * Logique pure des codes de secours (docs/paquet-2fa.md §2 décision #7, §3.8) :
 * génération, normalisation, hachage, vérification. La persistance (entités
 * RecoveryCode) est faite par les contrôleurs, qui marquent le code utilisé.
 */
class RecoveryCodeService
{
    public const COUNT = 10;

    /** Alphabet sans caractères ambigus (0/o, 1/l/i) : 32 symboles = 5 bits chacun. */
    protected const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

    /**
     * @return string[] codes en clair au format xxxx-xxxx, à afficher une seule fois
     */
    public function generate(int $count = self::COUNT): array
    {
        $codes = [];
        while (count($codes) < $count) {
            $codes[$this->randomCode()] = true;
        }

        return array_keys($codes);
    }

    public function hash(string $code): string
    {
        return password_hash($this->normalize($code), PASSWORD_DEFAULT);
    }

    /**
     * Minuscules, tirets et espaces ignorés.
     */
    public function normalize(string $code): string
    {
        return strtolower(str_replace(['-', ' '], '', trim($code)));
    }

    public function looksLikeRecoveryCode(string $input): bool
    {
        return (bool) preg_match('/^[a-z0-9]{8}$/', $this->normalize($input));
    }

    public function verify(string $input, string $hash): bool
    {
        $normalized = $this->normalize($input);
        if (strlen($normalized) !== 8) {
            return false;
        }

        return password_verify($normalized, $hash);
    }

    protected function randomCode(): string
    {
        $max = strlen(self::ALPHABET) - 1;
        $raw = '';
        for ($i = 0; $i < 8; $i++) {
            $raw .= self::ALPHABET[random_int(0, $max)];
        }

        return substr($raw, 0, 4) . '-' . substr($raw, 4);
    }
}
