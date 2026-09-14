<?php

namespace TackTack\TwoFactor\Service;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Exception\BadFormatException;
use Defuse\Crypto\Exception\EnvironmentIsBrokenException;
use Defuse\Crypto\Exception\WrongKeyOrModifiedCiphertextException;
use Defuse\Crypto\Key;

/**
 * Chiffrement au repos du secret TOTP, avec defuse/php-encryption
 * (docs/paquet-2fa.md §2 décision #6, §2 décision #12).
 *
 * La clé vit dans la variable d'environnement TWOFA_ENCRYPTION_KEY, jamais en base.
 * Ni cette classe ni aucun appelant ne doit journaliser la clé ou un secret en clair
 * (voir §3.9).
 */
class SecretCipher
{
    public const ENV_VAR = 'TWOFA_ENCRYPTION_KEY';

    /**
     * Lit et valide la clé depuis l'environnement.
     *
     * @throws \RuntimeException si la variable est absente ou son contenu invalide.
     *                           Le message ne contient jamais la valeur lue.
     */
    public function loadKey(): Key
    {
        $ascii = getenv(self::ENV_VAR);
        if ($ascii === false || $ascii === '') {
            throw new \RuntimeException(sprintf(
                'La variable d\'environnement %s est absente. Générez-en une avec `concrete/bin/concrete 2fa:generate-key`.',
                self::ENV_VAR
            ));
        }

        try {
            return Key::loadFromAsciiSafeString($ascii);
        } catch (BadFormatException|EnvironmentIsBrokenException $e) {
            throw new \RuntimeException(sprintf(
                'La variable d\'environnement %s ne contient pas une clé valide.',
                self::ENV_VAR
            ), 0, $e);
        }
    }

    /**
     * true si TWOFA_ENCRYPTION_KEY est présente et lisible comme clé defuse valide,
     * sans lancer d'exception. Utilisé par install() (décision #12) et par la
     * commande 2fa:status.
     */
    public function isKeyConfigured(): bool
    {
        try {
            $this->loadKey();

            return true;
        } catch (\RuntimeException $e) {
            return false;
        }
    }

    /**
     * Génère une nouvelle clé au format ASCII sûr, à placer dans TWOFA_ENCRYPTION_KEY.
     * Utilisé par la commande 2fa:generate-key (§3.10).
     */
    public function generateKey(): string
    {
        return Key::createNewRandomKey()->saveToAsciiSafeString();
    }

    public function encrypt(string $plaintext): string
    {
        return Crypto::encrypt($plaintext, $this->loadKey());
    }

    /**
     * @throws \RuntimeException si le texte chiffré ne correspond pas à la clé
     *                           actuelle (clé changée, donnée corrompue).
     */
    public function decrypt(string $ciphertext): string
    {
        try {
            return Crypto::decrypt($ciphertext, $this->loadKey());
        } catch (WrongKeyOrModifiedCiphertextException $e) {
            throw new \RuntimeException('Le secret chiffré ne correspond pas à la clé actuelle.', 0, $e);
        }
    }
}
