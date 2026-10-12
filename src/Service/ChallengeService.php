<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\Entity\Permission\IpAccessControlCategory;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerFactory;
use Concrete\Core\Permission\IpAccessControlService;
use Concrete\Core\Support\Facade\Facade;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Concrete\Package\Tacktack2fa\Controller as PackageController;
use TackTack\TwoFactor\Entity\Credential;

/**
 * Vérification du code de l'écran de challenge (docs/paquet-2fa.md §3.4, étapes 3 à 5).
 *
 * Les écritures qui protègent contre le rejeu (pas de temps, code de secours) et le
 * compteur d'échecs sont des UPDATE conditionnels ou atomiques en SQL : deux requêtes
 * simultanées avec le même code ne peuvent pas réussir toutes les deux, et des essais
 * parallèles ne contournent pas le plafond de 5 échecs.
 */
class ChallengeService
{
    public const OK = 'ok';
    public const OK_RECOVERY = 'ok_recovery';
    public const FAILED = 'failed';
    /** Verrou utilisateur ou IP bannie : aucune vérification n'a été faite. */
    public const LOCKED = 'locked';
    /** Cet échec vient de poser le verrou. */
    public const JUST_LOCKED = 'just_locked';

    protected $em;
    protected $totp;
    protected $cipher;
    protected $recovery;
    protected $throttle;
    protected $loggerFactory;
    /** @var IpAccessControlService|null construit à la demande, jamais injecté : le conteneur en fabriquerait un avec une catégorie vide */
    protected $ipService;

    /** @var int|null nombre de codes de secours restants après un succès par code de secours */
    protected $remainingRecoveryCodes;

    public function __construct(
        EntityManagerInterface $em,
        TotpService $totp,
        SecretCipher $cipher,
        RecoveryCodeService $recovery,
        Throttle $throttle,
        LoggerFactory $loggerFactory
    ) {
        $this->em = $em;
        $this->totp = $totp;
        $this->cipher = $cipher;
        $this->recovery = $recovery;
        $this->throttle = $throttle;
        $this->loggerFactory = $loggerFactory;
    }

    public function getRemainingRecoveryCodes(): ?int
    {
        return $this->remainingRecoveryCodes;
    }

    /**
     * @param bool $allowRecovery false pour les actions qui exigent un code TOTP (régénération des codes)
     */
    public function attempt(int $uID, string $input, bool $allowRecovery = true): string
    {
        $this->remainingRecoveryCodes = null;
        $credential = $this->em->find(Credential::class, $uID);
        if ($credential === null || !$credential->isConfirmed()) {
            return self::FAILED;
        }
        // Les UPDATE conditionnels ci-dessous passent par SQL : relire l'état courant.
        $this->em->refresh($credential);

        $locked = $credential->getLockedUntil() !== null
            && $this->throttle->isLocked(DateTimeImmutable::createFromMutable($credential->getLockedUntil()));
        if ($locked || $this->isIpBanned()) {
            return self::LOCKED;
        }

        $input = trim($input);
        if ($this->recovery->looksLikeRecoveryCode($input)) {
            $result = $allowRecovery ? $this->tryRecoveryCode($uID, $input) : self::FAILED;
        } else {
            $result = $this->tryTotp($credential, $input) ? self::OK : self::FAILED;
        }

        if ($result === self::FAILED) {
            return $this->registerFailure($uID);
        }

        $this->exec('UPDATE TwoFactorCredentials SET failedAttempts = 0, lockedUntil = NULL WHERE uID = :uID', ['uID' => $uID]);

        return $result;
    }

    protected function tryTotp(Credential $credential, string $input): bool
    {
        try {
            $secret = $this->cipher->decrypt((string) $credential->getSecret());
        } catch (\RuntimeException $e) {
            // Décision #12 : clé absente ou invalide → TOTP refusé (échec fermé), journalisé.
            // Les codes de secours restent utilisables.
            $this->log()->warning('2FA : secret illisible (clé de chiffrement absente, invalide ou changée) pour l\'utilisateur ' . $credential->getUserID() . '.');

            return false;
        }

        $step = $this->totp->verify($secret, $input, $credential->getLastTimestep());
        if ($step === null) {
            return false;
        }

        // Rejeu : le pas ne s'enregistre que s'il est strictement plus récent que celui en base.
        $affected = $this->exec(
            'UPDATE TwoFactorCredentials SET lastTimestep = :step WHERE uID = :uID AND (lastTimestep IS NULL OR lastTimestep < :step2)',
            ['step' => $step, 'step2' => $step, 'uID' => $credential->getUserID()]
        );

        return $affected === 1;
    }

    protected function tryRecoveryCode(int $uID, string $input): string
    {
        $rows = $this->em->getConnection()->fetchAllAssociative(
            'SELECT id, codeHash FROM TwoFactorRecoveryCodes WHERE uID = :uID AND usedAt IS NULL',
            ['uID' => $uID]
        );
        foreach ($rows as $row) {
            if (!$this->recovery->verify($input, $row['codeHash'])) {
                continue;
            }
            // Usage unique : seul le premier UPDATE voit usedAt IS NULL.
            $affected = $this->exec(
                'UPDATE TwoFactorRecoveryCodes SET usedAt = :now WHERE id = :id AND usedAt IS NULL',
                ['now' => $this->now(), 'id' => $row['id']]
            );
            if ($affected !== 1) {
                return self::FAILED;
            }
            $this->remainingRecoveryCodes = (int) $this->em->getConnection()->fetchOne(
                'SELECT COUNT(*) FROM TwoFactorRecoveryCodes WHERE uID = :uID AND usedAt IS NULL',
                ['uID' => $uID]
            );
            $this->log()->warning(sprintf('2FA : code de secours utilisé par l\'utilisateur %d (%d restants).', $uID, $this->remainingRecoveryCodes));

            return self::OK_RECOVERY;
        }

        return self::FAILED;
    }

    protected function registerFailure(int $uID): string
    {
        // Incrément atomique, puis lecture : des essais parallèles ne perdent aucune tentative.
        $this->exec('UPDATE TwoFactorCredentials SET failedAttempts = failedAttempts + 1 WHERE uID = :uID', ['uID' => $uID]);
        $attempts = (int) $this->em->getConnection()->fetchOne('SELECT failedAttempts FROM TwoFactorCredentials WHERE uID = :uID', ['uID' => $uID]);

        $ip = $this->ipService();
        if ($ip !== null) {
            $ip->registerEvent();
            if ($ip->isThresholdReached()) {
                $ip->addToDenylistForThresholdReached();
            }
        }

        $state = $this->throttle->registerFailure($attempts - 1);
        if (!$state['locked']) {
            $this->log()->notice(sprintf('2FA : code refusé pour l\'utilisateur %d.', $uID));

            return self::FAILED;
        }

        $this->exec(
            'UPDATE TwoFactorCredentials SET failedAttempts = 0, lockedUntil = :until WHERE uID = :uID',
            ['until' => $state['lockedUntil']->format('Y-m-d H:i:s'), 'uID' => $uID]
        );
        $this->log()->warning(sprintf('2FA : utilisateur %d verrouillé après %d échecs.', $uID, Throttle::MAX_ATTEMPTS));

        return self::JUST_LOCKED;
    }

    protected function isIpBanned(): bool
    {
        $ip = $this->ipService();

        return $ip !== null && ($ip->isDenylisted() || $ip->isThresholdReached());
    }

    protected function ipService(): ?IpAccessControlService
    {
        if ($this->ipService !== null) {
            return $this->ipService;
        }
        $category = $this->em->getRepository(IpAccessControlCategory::class)
            ->findOneBy(['handle' => PackageController::IP_CATEGORY_HANDLE]);
        if ($category === null) {
            return null;
        }

        return $this->ipService = Facade::getFacadeApplication()->make(IpAccessControlService::class, ['category' => $category]);
    }

    protected function exec(string $sql, array $params): int
    {
        return (int) $this->em->getConnection()->executeStatement($sql, $params);
    }

    protected function now(): string
    {
        return (new DateTimeImmutable())->format('Y-m-d H:i:s');
    }

    protected function log()
    {
        return $this->loggerFactory->createLogger(Channels::CHANNEL_AUTHENTICATION);
    }
}
