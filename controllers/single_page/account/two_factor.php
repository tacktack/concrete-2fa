<?php

namespace Concrete\Package\Tacktack2fa\Controller\SinglePage\Account;

use Concrete\Core\Page\Controller\AccountPageController;
use Concrete\Core\User\User;
use TackTack\TwoFactor\Service\EnrollmentException;
use TackTack\TwoFactor\Service\EnrollmentService;

/**
 * /account/two_factor — activation volontaire (docs/paquet-2fa.md §3.5, §3.6).
 *
 * Étape 3 : activation seulement. Régénération des codes et désactivation viennent à
 * l'étape 6. EnrollmentService refuse tout utilisateur déjà enrôlé, donc cette page ne
 * peut jamais remplacer un secret existant, quel que soit l'état de la session.
 */
class TwoFactor extends AccountPageController
{
    public const TOKEN = 'tacktack_2fa_enroll';

    public function view()
    {
        $this->showStatus();
    }

    public function confirm()
    {
        if (!$this->token->validate(self::TOKEN)) {
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

        $this->set('enrolled', true);
        $this->set('codes', $codes);
        $this->set('continueUrl', (string) $this->app->make('url/manager')->resolve(['/account/two_factor']));
        // Les codes de secours ne s'affichent qu'une fois : réponse non cachable.
        if (!headers_sent()) {
            header('Cache-Control: no-store, private');
        }
    }

    protected function showStatus(): void
    {
        $service = $this->app->make(EnrollmentService::class);
        $user = $this->app->make(User::class);

        if ($service->isEnrolled($user)) {
            $this->set('enrolled', true);

            return;
        }

        $data = $service->begin($user);
        $this->set('enrolled', false);
        $this->set('secret', $data['groupedSecret']);
        $this->set('qrSvg', $data['qrSvg']);
        $this->set('formAction', (string) $this->action('confirm'));
        $this->set('tokenName', self::TOKEN);
        if (!headers_sent()) {
            header('Cache-Control: no-store, private');
        }
    }
}
