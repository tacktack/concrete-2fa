<?php

namespace TackTack\TwoFactor\Service;

use PragmaRX\Google2FA\Google2FA;

/**
 * TOTP RFC 6238 : SHA-1, 6 chiffres, pas de 30 s, tolérance ±1 pas
 * (docs/paquet-2fa.md §2 décisions #4 et #5).
 *
 * La comparaison des codes est faite par google2fa avec hash_equals (temps constant).
 */
class TotpService
{
    public const WINDOW = 1;

    /** @var Google2FA */
    protected $google2fa;

    public function __construct(?Google2FA $google2fa = null)
    {
        $this->google2fa = $google2fa ?? new Google2FA();
        $this->google2fa->setAlgorithm('sha1');
        $this->google2fa->setOneTimePasswordLength(6);
        $this->google2fa->setKeyRegeneration(30);
        $this->google2fa->setWindow(self::WINDOW);
    }

    /**
     * Secret de 160 bits (32 caractères base32 = 20 octets) : taille recommandée par le RFC 4226.
     */
    public function generateSecret(): string
    {
        return $this->google2fa->generateSecretKey(32);
    }

    /**
     * Pas de temps courant (secondes Unix / 30).
     */
    public function currentTimestep(): int
    {
        return (int) $this->google2fa->getTimestamp();
    }

    /**
     * Vérifie un code et refuse tout pas ≤ $lastTimestep (protection contre le rejeu).
     *
     * @param int|null $lastTimestep dernier pas accepté pour cet utilisateur
     * @param int|null $timestep     pas de temps de référence (défaut : maintenant ; sert aux tests)
     *
     * @return int|null le pas de temps du code accepté, à enregistrer ; null si refusé
     */
    public function verify(string $secret, string $code, ?int $lastTimestep = null, ?int $timestep = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code);
        if (!is_string($code) || !preg_match('/^\d{6}$/', $code)) {
            return null;
        }

        try {
            // Un oldTimestamp non null est indispensable : sans lui, google2fa renvoie
            // true au lieu du pas trouvé.
            $result = $this->google2fa->verifyKeyNewer(
                $secret,
                $code,
                $lastTimestep ?? -1,
                self::WINDOW,
                $timestep
            );
        } catch (\Throwable $e) {
            // Secret invalide : refus, jamais d'exception vers l'appelant.
            return null;
        }

        return is_int($result) ? $result : null;
    }

    /**
     * Code attendu à un pas donné. Réservé aux tests.
     */
    public function codeAt(string $secret, int $timestep): string
    {
        return $this->google2fa->oathTotp($secret, $timestep);
    }

    /**
     * URI otpauth:// du QR code (§3.5). Issuer et compte sont encodés.
     */
    public function provisioningUri(string $issuer, string $account, string $secret): string
    {
        return $this->google2fa->getQRCodeUrl($issuer, $account, $secret);
    }
}
