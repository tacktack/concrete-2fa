<?php

namespace TackTack\TwoFactor\Entity;

use Concrete\Core\Entity\User\User;
use DateTime;
use Doctrine\ORM\Mapping as ORM;

/**
 * Un code de secours à usage unique (docs/paquet-2fa.md §3.8, décision #7 — remplace
 * le « mot de passe d'urgence » du paquet marketplace, voir §2.1).
 *
 * uID est une association ManyToOne, pas une clé primaire partagée comme dans
 * Credential : un utilisateur a plusieurs codes. onDelete="CASCADE" au niveau de la
 * base garantit la suppression même par UserInfo::delete() (SQL brut, voir
 * public/concrete/src/User/UserInfo.php) — Concrete ne passe jamais par
 * l'EntityManager pour supprimer un utilisateur, donc seule une vraie contrainte de
 * clé étrangère (et non un cascade Doctrine applicatif) fonctionne ici.
 *
 * @ORM\Entity
 * @ORM\Table(name="TwoFactorRecoveryCodes", indexes={
 *     @ORM\Index(name="idx_two_factor_recovery_codes_uid", columns={"uID"})
 * })
 */
class RecoveryCode
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer", options={"unsigned": true})
     * @ORM\GeneratedValue(strategy="AUTO")
     *
     * @var int
     */
    protected $id;

    /**
     * @ORM\ManyToOne(targetEntity="Concrete\Core\Entity\User\User")
     * @ORM\JoinColumn(name="uID", referencedColumnName="uID", nullable=false, onDelete="CASCADE")
     *
     * @var User
     */
    protected $user;

    /**
     * Hachage password_hash() du code (format xxxx-xxxx, §3.8). Le code en clair
     * n'est jamais stocké.
     *
     * @ORM\Column(type="string", length=255)
     *
     * @var string
     */
    protected $codeHash;

    /**
     * Non null = déjà utilisé (à usage unique).
     *
     * @ORM\Column(type="datetime", nullable=true)
     *
     * @var DateTime|null
     */
    protected $usedAt;

    /**
     * @ORM\Column(type="datetime")
     *
     * @var DateTime
     */
    protected $createdAt;

    public function __construct(User $user, string $codeHash)
    {
        $this->user = $user;
        $this->codeHash = $codeHash;
        $this->createdAt = new DateTime();
    }

    public function getId(): int
    {
        return $this->id;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getCodeHash(): string
    {
        return $this->codeHash;
    }

    public function getUsedAt(): ?DateTime
    {
        return $this->usedAt;
    }

    public function markUsed(): self
    {
        $this->usedAt = new DateTime();

        return $this;
    }

    public function isUsed(): bool
    {
        return $this->usedAt !== null;
    }

    public function getCreatedAt(): DateTime
    {
        return $this->createdAt;
    }
}
