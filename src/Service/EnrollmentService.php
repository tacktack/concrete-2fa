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
 * Enrôlement TOTP, partagé par /ccm/2fa/enroll (forcé) et /account/two_factor
 * (volontaire) — docs/paquet-2fa.md §3.5. L'appelant vérifie l'état et le jeton CSRF ;
 * ce service refuse en plus de toucher à un utilisateur déjà enrôlé, quel que soit
 * l'appelant (le secret existant ne doit jamais être remplaçable en v1).
 */
class EnrollmentService
{
    protected $em;
    protected $totp;
    protected $cipher;
    protected $recovery;
    protected $qr;
    protected $session;
    protected $notifier;
    protected $config;
    protected $sites;
    protected $loggerFactory;

    public function __construct(
        EntityManagerInterface $em,
        TotpService $totp,
        SecretCipher $cipher,
        RecoveryCodeService $recovery,
        QrCodeService $qr,
        SessionState $session,
        Notifier $notifier,
        PolicyConfig $config,
        SiteService $sites,
        LoggerFactory $loggerFactory
    ) {
        $this->em = $em;
        $this->totp = $totp;
        $this->cipher = $cipher;
        $this->recovery = $recovery;
        $this->qr = $qr;
        $this->session = $session;
        $this->notifier = $notifier;
        $this->config = $config;
        $this->sites = $sites;
        $this->loggerFactory = $loggerFactory;
    }

    public function isEnrolled(User $user): bool
    {
        $credential = $this->em->find(Credential::class, (int) $user->getUserID());

        return $credential !== null && $credential->isConfirmed();
    }

    /**
     * Données d'affichage de l'enrôlement. Le secret reste stable entre deux GET (un
     * rafraîchissement ne doit pas invalider un scan en cours) et ne touche pas la base.
     *
     * @return array{secret:string, groupedSecret:string, qrSvg:string}
     */
    public function begin(User $user): array
    {
        if ($this->isEnrolled($user)) {
            throw new EnrollmentException(t('Two-factor authentication is already set up for this account.'));
        }

        $uID = (int) $user->getUserID();
        $secret = $this->session->getPendingSecret($uID);
        if ($secret === null) {
            $secret = $this->totp->generateSecret();
            $this->session->setPendingSecret($uID, $secret);
        }

        $uri = $this->totp->provisioningUri($this->issuer(), (string) $user->getUserInfoObject()->getUserEmail(), $secret);

        return [
            'secret' => $secret,
            'groupedSecret' => trim(chunk_split($secret, 4, ' ')),
            'qrSvg' => $this->qr->svg($uri),
        ];
    }

    /**
     * Confirme l'enrôlement avec un code valide pour le secret de session.
     *
     * @throws EnrollmentException
     *
     * @return string[] codes de secours en clair, à afficher une seule fois
     */
    public function confirm(User $user, string $code): array
    {
        $uID = (int) $user->getUserID();
        $log = $this->loggerFactory->createLogger(Channels::CHANNEL_AUTHENTICATION);

        $secret = $this->session->getPendingSecret($uID);
        if ($secret === null) {
            throw new EnrollmentException(t('Your setup session has expired. Reload the page and scan the QR code again.'));
        }

        $step = $this->totp->verify($secret, $code, null);
        if ($step === null) {
            throw new EnrollmentException(t('The code is not valid. Check the code in your app and try again.'));
        }

        if (!$this->cipher->isKeyConfigured()) {
            $log->warning('2FA : enrôlement impossible, la clé de chiffrement est absente ou invalide.');
            throw new EnrollmentException(t('Two-factor authentication cannot be set up right now. Contact the site administrator.'));
        }

        $codes = $this->recovery->generate();

        $this->em->wrapInTransaction(function () use ($uID, $secret, $step, $codes) {
            $credential = $this->em->find(Credential::class, $uID);
            if ($credential === null) {
                $credential = new Credential($this->em->getReference(UserEntity::class, $uID));
                $this->em->persist($credential);
            } elseif ($credential->isConfirmed()) {
                throw new EnrollmentException(t('Two-factor authentication is already set up for this account.'));
            }

            $credential
                ->setSecret($this->cipher->encrypt($secret))
                ->setConfirmedAt(new \DateTime())
                // Le code d'enrôlement ne doit pas pouvoir resservir dans sa fenêtre (décision #5).
                ->setLastTimestep($step)
                ->setFailedAttempts(0)
                ->setLockedUntil(null);

            $this->em->createQuery('DELETE FROM ' . RecoveryCode::class . ' r WHERE IDENTITY(r.user) = :uID')
                ->setParameter('uID', $uID)
                ->execute();

            $userRef = $this->em->getReference(UserEntity::class, $uID);
            foreach ($codes as $plain) {
                $this->em->persist(new RecoveryCode($userRef, $this->recovery->hash($plain)));
            }
        });

        // L'utilisateur vient de fournir un code : la session est vérifiée.
        $this->session->markVerified($uID);
        $this->session->clearPendingSecret();

        $log->notice(sprintf('2FA activée pour l\'utilisateur %d.', $uID));

        $email = (string) $user->getUserInfoObject()->getUserEmail();
        if ($email !== '') {
            $this->notifier->enabled($email, $this->siteName());
        }

        return $codes;
    }

    protected function issuer(): string
    {
        return $this->config->issuer() ?? $this->siteName();
    }

    protected function siteName(): string
    {
        $site = $this->sites->getSite();

        return $site ? (string) $site->getSiteName() : 'Concrete';
    }
}
