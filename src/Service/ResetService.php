<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\Entity\User\User as UserEntity;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerFactory;
use Concrete\Core\Site\Service as SiteService;
use Concrete\Core\User\User;
use DateTime;
use Doctrine\ORM\EntityManagerInterface;
use TackTack\TwoFactor\Entity\Credential;
use TackTack\TwoFactor\Entity\RecoveryCode;

/**
 * Réinitialisation de la 2FA d'un utilisateur et levée de verrou, par un administrateur ou
 * en ligne de commande. Les garde-fous (permission, jeton
 * CSRF, mot de passe de l'administrateur, compte propre) sont à la charge de l'appelant
 * web ; la ligne de commande n'en a pas (l'accès au serveur est hors du modèle de menace).
 */
class ResetService
{
    /**
     * Début de grâce « déjà écoulé » : après une réinitialisation, un utilisateur imposé par
     * la politique doit s'enrôler dès la connexion suivante.
     */
    public const GRACE_EXPIRED = '2000-01-01 00:00:00';

    protected $em;
    protected $state;
    protected $notifier;
    protected $sites;
    protected $loggerFactory;

    public function __construct(EntityManagerInterface $em, UserState $state, Notifier $notifier, SiteService $sites, LoggerFactory $loggerFactory)
    {
        $this->em = $em;
        $this->state = $state;
        $this->notifier = $notifier;
        $this->sites = $sites;
        $this->loggerFactory = $loggerFactory;
    }

    /**
     * Supprime secret et codes de secours, lève les verrous.
     *
     * @param string $actor qui agit, pour le journal (« administrateur X », « ligne de commande »)
     *
     * @throws EnrollmentException utilisateur introuvable
     */
    public function reset(int $uID, string $actor): void
    {
        $user = User::getByUserID($uID);
        if (!$user) {
            throw new EnrollmentException(t('User not found.'));
        }

        $this->em->wrapInTransaction(function () use ($uID, $user) {
            $this->em->createQuery('DELETE FROM ' . RecoveryCode::class . ' r WHERE IDENTITY(r.user) = :uID')
                ->setParameter('uID', $uID)
                ->execute();

            $credential = $this->em->find(Credential::class, $uID);
            if (!$this->state->isRequired($user)) {
                // Non imposé : plus aucune raison de garder une ligne.
                if ($credential !== null) {
                    $this->em->remove($credential);
                }

                return;
            }
            if ($credential === null) {
                $credential = new Credential($this->em->getReference(UserEntity::class, $uID));
                $this->em->persist($credential);
            }
            $credential
                ->setSecret(null)
                ->setConfirmedAt(null)
                ->setLastTimestep(null)
                ->setFailedAttempts(0)
                ->setLockedUntil(null)
                ->setEnforcementStartedAt(new DateTime(self::GRACE_EXPIRED));
        });

        $this->log()->warning(sprintf('2FA : réinitialisée pour l\'utilisateur %d par %s.', $uID, $actor));

        $email = (string) $user->getUserInfoObject()->getUserEmail();
        if ($email !== '') {
            $site = $this->sites->getSite();
            $this->notifier->resetByOther($email, $site ? (string) $site->getSiteName() : 'Concrete');
        }
    }

    /**
     * Lève le verrou utilisateur et remet le compteur d'échecs à zéro.
     */
    public function liftLock(int $uID, string $actor): void
    {
        $this->em->getConnection()->executeStatement(
            'UPDATE TwoFactorCredentials SET failedAttempts = 0, lockedUntil = NULL WHERE uID = :uID',
            ['uID' => $uID]
        );
        $this->log()->warning(sprintf('2FA : verrou levé pour l\'utilisateur %d par %s.', $uID, $actor));
    }

    /**
     * @return int[] identifiants de tous les utilisateurs ayant une ligne
     */
    public function allUserIDs(): array
    {
        return array_map('intval', $this->em->getConnection()->fetchFirstColumn('SELECT uID FROM TwoFactorCredentials'));
    }

    protected function log()
    {
        return $this->loggerFactory->createLogger(Channels::CHANNEL_AUTHENTICATION);
    }
}
