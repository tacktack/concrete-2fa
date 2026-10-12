<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\Config\Repository\Repository;
use Concrete\Core\Entity\User\User as UserEntity;
use Concrete\Core\User\User;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use TackTack\TwoFactor\Entity\Credential;

/**
 * Collecte les entrées de PolicyResolver pour l'utilisateur courant et en tire l'état
 * 2FA (docs/paquet-2fa.md §3.2). C'est la source unique de l'état : le middleware
 * (étape 4) et chaque contrôleur /ccm/2fa/* passent par ici.
 */
class UserState
{
    /** @var EntityManagerInterface */
    protected $em;

    /** @var PolicyResolver */
    protected $resolver;

    /** @var SessionState */
    protected $session;

    /** @var Repository */
    protected $config;

    public function __construct(EntityManagerInterface $em, PolicyResolver $resolver, SessionState $session, Repository $config)
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
     * Concerné = super utilisateur (uID 1), membre d'un groupe obligatoire, ou déjà enrôlé
     * (décision #10).
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
     * enrôlement volontaire. Seuls les utilisateurs non imposés peuvent désactiver leur 2FA (§3.6).
     */
    public function isRequired(User $user): bool
    {
        if ((int) $user->getUserID() === USER_SUPER_ID) {
            return true;
        }
        $required = array_map('intval', (array) $this->config->get('tacktack_2fa::policy.groups', []));

        return count(array_intersect($required, array_map('intval', $user->getUserGroups()))) > 0;
    }

    public function resolve(User $user): string
    {
        $uID = (int) $user->getUserID();
        $credential = $this->getCredential($uID);
        $enrolled = $credential !== null && $credential->isConfirmed();
        $concerned = $this->isConcerned($user, $credential);

        // Premier constat « concerné et non enrôlé » : le délai de grâce démarre ici.
        if ($concerned && !$enrolled && ($credential === null || $credential->getEnforcementStartedAt() === null)) {
            if ($credential === null) {
                $credential = new Credential($this->em->getReference(UserEntity::class, $uID));
                $this->em->persist($credential);
            }
            $credential->setEnforcementStartedAt(new \DateTime());
            $this->em->flush();
        }

        $started = $credential !== null && $credential->getEnforcementStartedAt() !== null
            ? DateTimeImmutable::createFromMutable($credential->getEnforcementStartedAt())
            : null;

        return $this->resolver->resolve(
            $uID,
            $enrolled,
            $concerned,
            $started,
            (int) $this->config->get('tacktack_2fa::policy.grace_days', 7),
            $this->session->getVerified()
        );
    }
}
