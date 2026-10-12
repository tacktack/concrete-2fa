<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\Entity\User\User as UserEntity;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerFactory;
use Concrete\Core\Site\Service as SiteService;
use Concrete\Core\User\User;
use Doctrine\ORM\EntityManagerInterface;
use TackTack\TwoFactor\Entity\Credential;
use TackTack\TwoFactor\Entity\RecoveryCode;

/**
 * Actions de la page /account/two_factor sur un compte déjà enrôlé (docs/paquet-2fa.md §3.6).
 * L'appelant vérifie le jeton CSRF propre à l'action et l'état « verified ».
 */
class AccountService
{
    protected $em;
    protected $challenge;
    protected $recovery;
    protected $state;
    protected $session;
    protected $notifier;
    protected $sites;
    protected $loggerFactory;

    public function __construct(
        EntityManagerInterface $em,
        ChallengeService $challenge,
        RecoveryCodeService $recovery,
        UserState $state,
        SessionState $session,
        Notifier $notifier,
        SiteService $sites,
        LoggerFactory $loggerFactory
    ) {
        $this->em = $em;
        $this->challenge = $challenge;
        $this->recovery = $recovery;
        $this->state = $state;
        $this->session = $session;
        $this->notifier = $notifier;
        $this->sites = $sites;
        $this->loggerFactory = $loggerFactory;
    }

    /**
     * @return array{enabledAt:?\DateTime, remaining:int, required:bool}
     */
    public function status(User $user): array
    {
        $uID = (int) $user->getUserID();
        $credential = $this->em->find(Credential::class, $uID);

        return [
            'enabledAt' => $credential !== null ? $credential->getConfirmedAt() : null,
            'remaining' => (int) $this->em->getConnection()->fetchOne(
                'SELECT COUNT(*) FROM TwoFactorRecoveryCodes WHERE uID = :uID AND usedAt IS NULL',
                ['uID' => $uID]
            ),
            'required' => $this->state->isRequired($user),
        ];
    }

    /**
     * Régénère les 10 codes de secours ; les anciens sont invalidés. Exige un code TOTP valide.
     *
     * @throws EnrollmentException
     *
     * @return string[] codes en clair, à afficher une seule fois
     */
    public function regenerateCodes(User $user, string $code): array
    {
        $uID = (int) $user->getUserID();
        $this->assertNotImpersonating($uID);
        $this->assertCode($uID, $code, false);

        $codes = $this->recovery->generate();
        $this->em->wrapInTransaction(function () use ($uID, $codes) {
            $this->deleteCodes($uID);
            $ref = $this->em->getReference(UserEntity::class, $uID);
            foreach ($codes as $plain) {
                $this->em->persist(new RecoveryCode($ref, $this->recovery->hash($plain)));
            }
        });

        $this->log()->notice(sprintf('2FA : codes de secours régénérés pour l\'utilisateur %d.', $uID));
        $this->mail($user, function (string $email, string $site) {
            $this->notifier->codesRegenerated($email, $site);
        });

        return $codes;
    }

    /**
     * Désactive la 2FA. Refusé si la politique l'impose ; exige le mot de passe actuel puis un
     * code (TOTP ou secours).
     *
     * @throws EnrollmentException
     */
    public function disable(User $user, string $password, string $code): void
    {
        $uID = (int) $user->getUserID();
        $this->assertNotImpersonating($uID);

        if ($this->state->isRequired($user)) {
            throw new EnrollmentException(t('Two-factor authentication is required for your account and cannot be disabled.'));
        }
        // Mot de passe d'abord : sans lui, une session détournée ne peut pas tenter de codes.
        if ($password === '' || !$user->getUserInfoObject()->passwordMatches($password)) {
            $this->log()->warning(sprintf('2FA : mot de passe refusé lors d\'une désactivation (utilisateur %d).', $uID));
            throw new EnrollmentException(t('The password is not valid.'));
        }
        $this->assertCode($uID, $code, true);

        $this->em->wrapInTransaction(function () use ($uID) {
            $this->deleteCodes($uID);
            $this->em->createQuery('DELETE FROM ' . Credential::class . ' c WHERE IDENTITY(c.user) = :uID')
                ->setParameter('uID', $uID)
                ->execute();
        });
        $this->session->clearVerified();

        $this->log()->notice(sprintf('2FA : désactivée par l\'utilisateur %d.', $uID));
        $this->mail($user, function (string $email, string $site) {
            $this->notifier->disabled($email, $site);
        });
    }

    protected function assertCode(int $uID, string $code, bool $allowRecovery): void
    {
        $result = $this->challenge->attempt($uID, $code, $allowRecovery);
        if ($result !== ChallengeService::OK && $result !== ChallengeService::OK_RECOVERY) {
            // Message générique : ni le verrou ni la configuration ne sont révélés (§3.4).
            throw new EnrollmentException(t('The code is not valid, or verification is temporarily unavailable.'));
        }
    }

    protected function deleteCodes(int $uID): void
    {
        $this->em->createQuery('DELETE FROM ' . RecoveryCode::class . ' r WHERE IDENTITY(r.user) = :uID')
            ->setParameter('uID', $uID)
            ->execute();
    }

    protected function mail(User $user, callable $send): void
    {
        $email = (string) $user->getUserInfoObject()->getUserEmail();
        if ($email === '') {
            return;
        }
        $site = $this->sites->getSite();
        $send($email, $site ? (string) $site->getSiteName() : 'Concrete');
    }

    /**
     * Pendant une session ouverte par le super utilisateur (« Se connecter en tant que »), la 2FA
     * de la cible ne se modifie pas : sinon on pourrait y enrôler son propre appareil (§3.3.1).
     *
     * @throws EnrollmentException
     */
    protected function assertNotImpersonating(int $uID): void
    {
        if ($this->session->isImpersonating($uID)) {
            throw new EnrollmentException(t('Access denied.'));
        }
    }

    protected function log()
    {
        return $this->loggerFactory->createLogger(Channels::CHANNEL_AUTHENTICATION);
    }
}
