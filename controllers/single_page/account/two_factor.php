<?php

namespace Concrete\Package\Tacktack2fa\Controller\SinglePage\Account;

use Concrete\Core\Page\Controller\AccountPageController;
use Concrete\Core\User\User;
use TackTack\TwoFactor\Service\AccountService;
use TackTack\TwoFactor\Service\EnrollmentException;
use TackTack\TwoFactor\Service\EnrollmentService;
use TackTack\TwoFactor\Service\PolicyResolver;
use TackTack\TwoFactor\Service\SessionState;
use TackTack\TwoFactor\Service\UserState;

/**
 * /account/two_factor — activation volontaire, statut, régénération des codes de secours et
 * désactivation.
 *
 * Chaque action est un POST avec son propre jeton CSRF. EnrollmentService refuse tout
 * utilisateur déjà enrôlé : cette page ne peut jamais remplacer un secret existant. Les
 * actions sur un compte enrôlé exigent en plus l'état « verified » (recalculé ici).
 */
class TwoFactor extends AccountPageController
{
    public const TOKEN_ENROLL = 'tacktack_2fa_enroll';
    public const TOKEN_REGENERATE = 'tacktack_2fa_regenerate';
    public const TOKEN_DISABLE = 'tacktack_2fa_disable';

    public function view()
    {
        $this->showStatus();
    }

    public function confirm()
    {
        if (!$this->token->validate(self::TOKEN_ENROLL)) {
            $this->error->add($this->token->getErrorMessage());
            $this->showStatus();

            return;
        }

        try {
            $codes = $this->app->make(EnrollmentService::class)
                ->confirm($this->app->make(User::class), (string) $this->request->request->get('code', ''));
        } catch (EnrollmentException $e) {
            $this->error->add($e->getMessage());
            $this->showStatus();

            return;
        }

        $this->showCodes($codes);
    }

    public function regenerate()
    {
        if (!$this->token->validate(self::TOKEN_REGENERATE)) {
            $this->error->add($this->token->getErrorMessage());
            $this->showStatus();

            return;
        }

        try {
            $this->assertVerified();
            $codes = $this->app->make(AccountService::class)
                ->regenerateCodes($this->app->make(User::class), (string) $this->request->request->get('code', ''));
        } catch (EnrollmentException $e) {
            $this->error->add($e->getMessage());
            $this->showStatus();

            return;
        }

        $this->showCodes($codes);
    }

    public function disable()
    {
        if (!$this->token->validate(self::TOKEN_DISABLE)) {
            $this->error->add($this->token->getErrorMessage());
            $this->showStatus();

            return;
        }

        try {
            $this->assertVerified();
            $this->app->make(AccountService::class)->disable(
                $this->app->make(User::class),
                (string) $this->request->request->get('password', ''),
                (string) $this->request->request->get('code', '')
            );
        } catch (EnrollmentException $e) {
            $this->error->add($e->getMessage());
            $this->showStatus();

            return;
        }

        $this->flash('success', t('Two-factor authentication has been disabled.'));

        return $this->buildRedirect($this->action('view'));
    }

    /**
     * @throws EnrollmentException si la session n'est pas « verified »
     */
    protected function assertVerified(): void
    {
        if ($this->isImpersonating()) {
            throw new EnrollmentException(t('Access denied.'));
        }
        $state = $this->app->make(UserState::class)->resolve($this->app->make(User::class));
        if ($state !== PolicyResolver::VERIFIED) {
            throw new EnrollmentException(t('Access denied.'));
        }
    }

    protected function showCodes(array $codes): void
    {
        $this->set('mode', 'codes');
        $this->set('codes', $codes);
        $this->set('continueUrl', (string) $this->action('view'));
        $this->noStore();
    }

    protected function isImpersonating(): bool
    {
        return $this->app->make(SessionState::class)->isImpersonating((int) $this->app->make(User::class)->getUserID());
    }

    protected function showStatus(): void
    {
        $user = $this->app->make(User::class);

        // Session ouverte par le super utilisateur : la 2FA de la cible ne se consulte
        // ni ne se modifie ici.
        if ($this->isImpersonating()) {
            $this->set('mode', 'impersonation');

            return;
        }
        $enrollment = $this->app->make(EnrollmentService::class);

        if ($enrollment->isEnrolled($user)) {
            $status = $this->app->make(AccountService::class)->status($user);
            $this->set('mode', 'status');
            $this->set('status', $status);
            $this->set('regenerateAction', (string) $this->action('regenerate'));
            $this->set('disableAction', (string) $this->action('disable'));
            $this->set('tokenRegenerate', self::TOKEN_REGENERATE);
            $this->set('tokenDisable', self::TOKEN_DISABLE);

            return;
        }

        $data = $enrollment->begin($user);
        $this->set('mode', 'enroll');
        $this->set('secret', $data['groupedSecret']);
        $this->set('qrSvg', $data['qrSvg']);
        $this->set('formAction', (string) $this->action('confirm'));
        $this->set('tokenName', self::TOKEN_ENROLL);
        $this->noStore();
    }

    protected function noStore(): void
    {
        if (!headers_sent()) {
            header('Cache-Control: no-store, private');
        }
    }
}
