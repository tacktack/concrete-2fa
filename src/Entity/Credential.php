<?php

namespace TackTack\TwoFactor\Entity;

use Concrete\Core\Entity\User\User;
use DateTime;
use Doctrine\ORM\Mapping as ORM;

/**
 * Une ligne par utilisateur enrôlé ou concerné par la politique 2FA
 * (docs/paquet-2fa.md §3.8, décision figée #11).
 *
 * uID sert à la fois de clé primaire et de clé étrangère vers Users.uID (association
 * "clé primaire partagée") : onDelete="CASCADE" au niveau de la base fait que la ligne
 * disparaît automatiquement à la suppression de l'utilisateur, y compris quand celle-ci
 * passe par UserInfo::delete() (SQL brut, pas par l'EntityManager) — voir la note dans
 * TwoFactorRecoveryCodes.
 *
 * @ORM\Entity
 * @ORM\Table(name="TwoFactorCredentials")
 */
class Credential
{
    /**
     * @ORM\Id
     * @ORM\OneToOne(targetEntity="Concrete\Core\Entity\User\User")
     * @ORM\JoinColumn(name="uID", referencedColumnName="uID", onDelete="CASCADE")
     *
     * @var User
     */
    protected $user;

    /**
     * Secret TOTP chiffré (defuse). Null tant que l'utilisateur n'a pas confirmé
     * son enrôlement (décision #12 : jamais en clair en base).
     *
     * @ORM\Column(type="text", nullable=true)
     *
     * @var string|null
     */
    protected $secret;

    /**
     * Non null = enrôlement confirmé (état "pending"/"verified" du §3.2).
     *
     * @ORM\Column(type="datetime", nullable=true)
     *
     * @var DateTime|null
     */
    protected $confirmedAt;

    /**
     * Dernier pas de temps TOTP accepté, pour la protection contre le rejeu
     * (décision #5).
     *
     * @ORM\Column(type="bigint", nullable=true)
     *
     * @var int|null
     */
    protected $lastTimestep;

    /**
     * @ORM\Column(type="integer")
     *
     * @var int
     */
    protected $failedAttempts = 0;

    /**
     * @ORM\Column(type="datetime", nullable=true)
     *
     * @var DateTime|null
     */
    protected $lockedUntil;

    /**
     * Début du délai de grâce (§3.2). Remis à null par une réinitialisation
     * administrateur, pour exiger l'enrôlement dès la connexion suivante.
     *
     * @ORM\Column(type="datetime", nullable=true)
     *
     * @var DateTime|null
     */
    protected $enforcementStartedAt;

    /**
     * @ORM\Column(type="datetime")
     *
     * @var DateTime
     */
    protected $createdAt;

    /**
     * @ORM\Column(type="datetime")
     *
     * @var DateTime
     */
    protected $updatedAt;

    public function __construct(User $user)
    {
        $this->user = $user;
        $this->createdAt = new DateTime();
        $this->updatedAt = new DateTime();
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getUserID(): int
    {
        return (int) $this->user->getUserID();
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    public function setSecret(?string $secret): self
    {
        $this->secret = $secret;
        $this->touch();

        return $this;
    }

    public function getConfirmedAt(): ?DateTime
    {
        return $this->confirmedAt;
    }

    public function setConfirmedAt(?DateTime $confirmedAt): self
    {
        $this->confirmedAt = $confirmedAt;
        $this->touch();

        return $this;
    }

    public function isConfirmed(): bool
    {
        return $this->confirmedAt !== null;
    }

    public function getLastTimestep(): ?int
    {
        return $this->lastTimestep;
    }

    public function setLastTimestep(?int $lastTimestep): self
    {
        $this->lastTimestep = $lastTimestep;
        $this->touch();

        return $this;
    }

    public function getFailedAttempts(): int
    {
        return $this->failedAttempts;
    }

    public function setFailedAttempts(int $failedAttempts): self
    {
        $this->failedAttempts = $failedAttempts;
        $this->touch();

        return $this;
    }

    public function getLockedUntil(): ?DateTime
    {
        return $this->lockedUntil;
    }

    public function setLockedUntil(?DateTime $lockedUntil): self
    {
        $this->lockedUntil = $lockedUntil;
        $this->touch();

        return $this;
    }

    public function isLocked(): bool
    {
        return $this->lockedUntil !== null && $this->lockedUntil > new DateTime();
    }

    public function getEnforcementStartedAt(): ?DateTime
    {
        return $this->enforcementStartedAt;
    }

    public function setEnforcementStartedAt(?DateTime $enforcementStartedAt): self
    {
        $this->enforcementStartedAt = $enforcementStartedAt;
        $this->touch();

        return $this;
    }

    public function getCreatedAt(): DateTime
    {
        return $this->createdAt;
    }

    public function getUpdatedAt(): DateTime
    {
        return $this->updatedAt;
    }

    private function touch(): void
    {
        $this->updatedAt = new DateTime();
    }
}
