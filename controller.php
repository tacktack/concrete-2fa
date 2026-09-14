<?php

namespace Concrete\Package\Tacktack2fa;

defined('C5_EXECUTE') or die('Access Denied.');

use Concrete\Core\Entity\Package as PackageEntity;
use Concrete\Core\Entity\Permission\IpAccessControlCategory;
use Concrete\Core\Error\UserMessageException;
use Concrete\Core\Package\Package;
use Concrete\Core\Permission\Access\Access;
use Concrete\Core\Permission\Access\Entity\GroupEntity;
use Concrete\Core\Permission\Key\Key as PermissionKey;
use Concrete\Core\User\Group\Group;
use Doctrine\ORM\EntityManagerInterface;
use TackTack\TwoFactor\Service\SecretCipher;

/**
 * Double authentification TOTP pour Concrete CMS 9.
 *
 * Architecture figée dans docs/paquet-2fa.md (dépôt Oli, ce paquet vit dans un dépôt
 * séparé). Ne pas rejouer les décisions qui y sont marquées "figée" sans les valider
 * d'abord dans ce document.
 */
class Controller extends Package
{
    /**
     * Handle de la catégorie de contrôle d'accès IP créée par ce paquet
     * (§2 décision #9 : 20 échecs / 10 min → bannissement 1 h). Visible au Dashboard
     * dans l'écran natif des contrôles d'accès IP du cœur.
     */
    const IP_CATEGORY_HANDLE = 'tacktack_2fa_failed_code';

    /**
     * Permission de tâche exigée pour réinitialiser la 2FA d'un autre utilisateur ou
     * lever un verrou depuis le Dashboard (§3.7). Accordée aux Administrateurs par
     * défaut à l'installation ; réattribuable comme toute permission de tâche.
     */
    const RESET_PERMISSION_HANDLE = 'tacktack_2fa_reset';

    /**
     * @var string
     */
    protected $appVersionRequired = '9.0.0';

    /**
     * @var string
     */
    protected $phpVersionRequired = '8.1';

    /**
     * @var string
     */
    protected $pkgHandle = 'tacktack_2fa';

    /**
     * @var string
     */
    protected $pkgVersion = '0.1.0';

    /**
     * Classes dans packages/tacktack_2fa/src/ → namespace \TackTack\TwoFactor.
     *
     * Sert aussi à DefaultPackageProvider pour découvrir les entités Doctrine de
     * src/Entity/ (voir Credential et RecoveryCode) : ne pas retirer même si
     * l'autoload Composer racine couvre déjà ce namespace.
     *
     * @var array
     */
    protected $pkgAutoloaderRegistries = [
        'src' => '\TackTack\TwoFactor',
    ];

    public function getPackageName()
    {
        return t('2FA');
    }

    public function getPackageDescription()
    {
        return t('Double authentification (TOTP) compatible Google Authenticator, Authy, etc.');
    }

    public function on_start()
    {
        $this->registerAutoload();
    }

    /**
     * Autoload des dépendances tierces si le paquet est distribué avec son propre
     * vendor/ (installation hors Composer). Sans effet quand Composer résout déjà
     * pragmarx/google2fa, bacon/bacon-qr-code et defuse/php-encryption dans le
     * vendor/ racine du site — c'est le cas normal pour ce paquet (docs/paquet-2fa.md
     * §3.11, §4).
     */
    protected function registerAutoload()
    {
        if (file_exists($this->getPackagePath() . '/vendor/autoload.php')) {
            require $this->getPackagePath() . '/vendor/autoload.php';
        }
    }

    /**
     * @return PackageEntity
     */
    public function install()
    {
        // §2 décision #12 : échec fermé si la clé de chiffrement est absente ou
        // invalide, AVANT toute écriture — parent::install() n'est pas encore
        // appelé, donc aucune ligne Packages n'est créée et l'installation peut être
        // retentée proprement une fois la clé en place.
        $this->assertEncryptionKeyConfigured();

        $pkg = parent::install();

        $this->installFailedCodeIpCategory($pkg);
        $this->installResetPermission($pkg);

        return $pkg;
    }

    public function upgrade()
    {
        // Pas de vérification de clé ici (contrairement à install()) : la garder à
        // jour est la responsabilité du contrôle explicite ajouté à l'étape 9 dans le
        // workflow de déploiement (docs/paquet-2fa.md §4), pas de ce code, pour ne
        // pas bloquer une mise à niveau du paquet lui-même si le déploiement échoue
        // pour une autre raison avant d'atteindre cette étape.
        parent::upgrade();

        $pkg = $this->getPackageEntity();
        $this->installFailedCodeIpCategory($pkg);
        $this->installResetPermission($pkg);
    }

    protected function assertEncryptionKeyConfigured(): void
    {
        $cipher = new SecretCipher();
        if (!$cipher->isKeyConfigured()) {
            throw new UserMessageException(t(
                'The environment variable %s is missing or invalid. Generate one with `concrete/bin/concrete 2fa:generate-key`, place it in your .env file, then retry the installation.',
                SecretCipher::ENV_VAR
            ));
        }
    }

    /**
     * Catégorie IP dédiée aux échecs de code 2FA (§2 décision #9). Idempotent :
     * appelée à la fois par install() et upgrade().
     */
    protected function installFailedCodeIpCategory(PackageEntity $pkg): void
    {
        $em = $this->app->make(EntityManagerInterface::class);
        $repo = $em->getRepository(IpAccessControlCategory::class);
        if ($repo->findOneBy(['handle' => self::IP_CATEGORY_HANDLE]) !== null) {
            return;
        }

        $category = new IpAccessControlCategory();
        $category
            ->setHandle(self::IP_CATEGORY_HANDLE)
            ->setName(t('2FA — Failed Codes'))
            ->setEnabled(true)
            ->setMaxEvents(20)
            ->setTimeWindow(600)
            ->setBanDuration(3600)
            ->setSiteSpecific(false)
            ->setPackage($pkg)
        ;
        $em->persist($category);
        $em->flush($category);
    }

    /**
     * Permission de tâche « tacktack_2fa_reset », accordée aux Administrateurs par
     * défaut (§3.7). Idempotent.
     */
    protected function installResetPermission(PackageEntity $pkg): void
    {
        $pk = PermissionKey::getByHandle(self::RESET_PERMISSION_HANDLE);
        if ($pk instanceof PermissionKey) {
            return;
        }

        $pk = PermissionKey::add(
            'admin',
            self::RESET_PERMISSION_HANDLE,
            t('Reset Two-Factor Authentication'),
            t("Controls whether a user can reset another user's two-factor authentication and lift 2FA lockouts from the Dashboard."),
            false,
            false,
            $pkg
        );

        $pa = $pk->getPermissionAccessObject();
        if (!is_object($pa)) {
            $pa = Access::create($pk);
        }

        $adminGroup = Group::getByID(ADMIN_GROUP_ID);
        if ($adminGroup) {
            $adminGroupEntity = GroupEntity::getOrCreate($adminGroup);
            $pa->addListItem($adminGroupEntity);
            $pt = $pk->getPermissionAssignmentObject();
            $pt->assignPermissionAccess($pa);
        }
    }
}
