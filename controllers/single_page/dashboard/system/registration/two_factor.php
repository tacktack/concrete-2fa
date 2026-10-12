<?php

namespace Concrete\Package\Tacktack2fa\Controller\SinglePage\Dashboard\System\Registration;

use Concrete\Core\Database\Connection\Connection;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerFactory;
use Concrete\Core\Page\Controller\DashboardPageController;
use Concrete\Core\Permission\Key\Key as PermissionKey;
use Concrete\Core\User\User;
use Concrete\Package\Tacktack2fa\Controller as PackageController;
use TackTack\TwoFactor\Service\EnrollmentException;
use TackTack\TwoFactor\Service\OverviewService;
use TackTack\TwoFactor\Service\PolicyConfig;
use TackTack\TwoFactor\Service\ResetService;

/**
 * /dashboard/system/registration/two_factor — réglages de la politique, liste des utilisateurs
 * concernés, réinitialisation et levée de verrou (docs/paquet-2fa.md §3.7).
 *
 * Réinitialiser et lever un verrou exigent : la permission de tâche « tacktack_2fa_reset »,
 * un POST avec jeton CSRF, la ressaisie du mot de passe de l'administrateur, et un compte
 * autre que le sien (on passe par la page de compte pour soi).
 */
class TwoFactor extends DashboardPageController
{
    public const TOKEN_SETTINGS = 'tacktack_2fa_settings';
    public const TOKEN_ACTION = 'tacktack_2fa_admin_action';

    public function view()
    {
        $config = $this->app->make(PolicyConfig::class);
        $this->set('selectedGroups', $config->groups());
        $this->set('graceDays', $config->graceDays());
        $this->set('issuer', (string) $config->issuer());
        $this->set('groups', $this->app->make(Connection::class)->fetchAllAssociative('SELECT gID, gName FROM `Groups` WHERE gID > ' . (int) REGISTERED_GROUP_ID . ' ORDER BY gName'));
        $this->set('users', $this->app->make(OverviewService::class)->concernedUsers());
        $this->set('canReset', $this->canReset());
        $me = $this->app->make(User::class);
        $this->set('myID', (int) $me->getUserID());
        $this->set('isSuper', (bool) $me->isSuperUser());
    }

    public function save_settings()
    {
        if (!$this->token->validate(self::TOKEN_SETTINGS)) {
            $this->error->add($this->token->getErrorMessage());
        }

        $groupIDs = [];
        foreach ((array) $this->request->request->get('groups', []) as $gID) {
            $gID = (int) $gID;
            if ($gID > REGISTERED_GROUP_ID && \Concrete\Core\User\Group\Group::getByID($gID)) {
                $groupIDs[] = $gID;
            }
        }
        $graceDays = $this->request->request->get('grace_days');
        if (!is_string($graceDays) || !ctype_digit($graceDays) || (int) $graceDays > 365) {
            $this->error->add(t('The grace period must be a number of days between 0 and 365.'));
        }
        $issuer = trim((string) $this->request->request->get('issuer', ''));
        if (mb_strlen($issuer) > 100) {
            $this->error->add(t('The name shown in authenticator apps is too long.'));
        }

        if (!$this->error->has()) {
            $this->app->make(PolicyConfig::class)->save($groupIDs, (int) $graceDays, $issuer === '' ? null : $issuer);
            $this->flash('success', t('Settings saved.'));

            return $this->buildRedirect($this->action('view'));
        }

        $this->view();
    }

    public function reset()
    {
        $this->adminAction(function (ResetService $service, int $uID, string $actor) {
            $service->reset($uID, $actor);
            $this->flash('success', t('Two-factor authentication has been reset for this user.'));
        });

        return $this->finish();
    }

    public function lift_lock()
    {
        $this->adminAction(function (ResetService $service, int $uID, string $actor) {
            $service->liftLock($uID, $actor);
            $this->flash('success', t('The lockout has been lifted.'));
        });

        return $this->finish();
    }

    protected function canReset(): bool
    {
        $pk = PermissionKey::getByHandle(PackageController::RESET_PERMISSION_HANDLE);

        return $pk !== null && $pk->validate();
    }

    /**
     * Applique les garde-fous communs, puis l'action. Les erreurs vont dans $this->error.
     */
    protected function adminAction(callable $action): void
    {
        if (!$this->token->validate(self::TOKEN_ACTION)) {
            $this->error->add($this->token->getErrorMessage());

            return;
        }
        if (!$this->canReset()) {
            $this->error->add(t('Access denied.'));

            return;
        }

        $me = $this->app->make(User::class);
        $uID = (int) $this->request->request->get('uID');
        if ($uID <= 0) {
            $this->error->add(t('User not found.'));

            return;
        }
        // Même règle que le cœur (UserInfoResponse::canEditUser) : seul le super utilisateur
        // peut agir sur le super utilisateur.
        if ($uID === (int) USER_SUPER_ID && !$me->isSuperUser()) {
            $this->error->add(t('Access denied.'));

            return;
        }
        if ($uID === (int) $me->getUserID()) {
            $this->error->add(t('You cannot do this on your own account. Use your account page instead.'));

            return;
        }
        $password = (string) $this->request->request->get('password', '');
        if ($password === '' || !$me->getUserInfoObject()->passwordMatches($password)) {
            $this->app->make(LoggerFactory::class)->createLogger(Channels::CHANNEL_AUTHENTICATION)
                ->warning(sprintf('2FA : mot de passe refusé à l\'administrateur %d sur une action du Dashboard (utilisateur visé : %d).', $me->getUserID(), $uID));
            $this->error->add(t('Your password is not valid.'));

            return;
        }

        try {
            $action($this->app->make(ResetService::class), $uID, sprintf('administrator %s (%d)', $me->getUserName(), $me->getUserID()));
        } catch (EnrollmentException $e) {
            $this->error->add($e->getMessage());
        }
    }

    protected function finish()
    {
        if ($this->error->has()) {
            $this->view();

            return;
        }

        return $this->buildRedirect($this->action('view'));
    }
}
