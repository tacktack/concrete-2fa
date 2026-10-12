<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\User\User;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use TackTack\TwoFactor\Entity\Credential;

/**
 * Collecte les entrées de PolicyResolver pour l'utilisateur courant et en tire l'état
 * 2FA. C'est la source unique de l'état : le middleware
 * et chaque contrôleur /ccm/2fa/* passent par ici.
 */
class UserState
{
    /** @var EntityManagerInterface */
    protected $em;

    /** @var PolicyResolver */
    protected $resolver;

    /** @var SessionState */
    protected $session;

    /** @var PolicyConfig */
    protected $config;

    public function __construct(EntityManagerInterface $em, PolicyResolver $resolver, SessionState $session, PolicyConfig $config)
    {
        $this->em = $em;
        $this->resolver = $resolver;
        $this->session = $session;
        $this->config = $config;
    }

    public function getCredential(int $uID): ?Credential
    {
        return $this->em->find(Credential::class, $uID);
    }

    /**
     * Concerné = super utilisateur (uID 1), membre d'un groupe obligatoire, ou déjà enrôlé.
     */
    public function isConcerned(User $user, ?Credential $credential): bool
    {
        if ($credential !== null && $credential->isConfirmed()) {
            return true;
        }

        return $this->isRequired($user);
    }

    /**
     * Imposé par la politique (super utilisateur ou groupe obligatoire), indépendamment d'un
     * enrôlement volontaire. Seuls les utilisateurs non imposés peuvent désactiver leur 2FA.
     */
    public function isRequired(User $user): bool
    {
        if ((int) $user->getUserID() === USER_SUPER_ID) {
            return true;
        }
        $required = $this->config->groups();

        return count(array_intersect($required, array_map('intval', $user->getUserGroups()))) > 0;
    }

    public function resolve(User $user): string
    {
        $uID = (int) $user->getUserID();
        $credential = $this->getCredential($uID);
        $enrolled = $credential !== null && $credential->isConfirmed();
        $concerned = $this->isConcerned($user, $credential);

        // Premier constat « concerné et non enrôlé » : le délai de grâce démarre ici. Plusieurs
        // requêtes parallèles peuvent faire ce constat en même temps : l'INSERT tolère le doublon
        // au lieu de laisser une violation de clé primaire fermer l'EntityManager (erreur 500).
        if ($concerned && !$enrolled && ($credential === null || $credential->getEnforcementStartedAt() === null)) {
            $this->startEnforcement($uID);
            if ($credential === null) {
                $credential = $this->getCredential($uID);
            } else {
                $this->em->refresh($credential);
            }
        }

        $started = $credential !== null && $credential->getEnforcementStartedAt() !== null
            ? DateTimeImmutable::createFromMutable($credential->getEnforcementStartedAt())
            : null;

        return $this->resolver->resolve(
            $uID,
            $enrolled,
            $concerned,
            $started,
            $this->config->graceDays(),
            $this->session->getVerified()
        );
    }

    protected function startEnforcement(int $uID): void
    {
        $now = date('Y-m-d H:i:s');
        $conn = $this->em->getConnection();
        $conn->executeStatement(
            'INSERT IGNORE INTO TwoFactorCredentials (uID, failedAttempts, enforcementStartedAt, createdAt, updatedAt) VALUES (:uID, 0, :n1, :n2, :n3)',
            ['uID' => $uID, 'n1' => $now, 'n2' => $now, 'n3' => $now]
        );
        $conn->executeStatement(
            'UPDATE TwoFactorCredentials SET enforcementStartedAt = :now, updatedAt = :now2 WHERE uID = :uID AND enforcementStartedAt IS NULL AND confirmedAt IS NULL',
            ['now' => $now, 'now2' => $now, 'uID' => $uID]
        );
    }
}
