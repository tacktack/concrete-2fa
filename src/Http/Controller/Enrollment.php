<?php

namespace TackTack\TwoFactor\Http\Controller;

use Concrete\Core\Controller\Controller;
use Concrete\Core\Routing\RedirectResponse;
use Concrete\Core\User\User;
use Concrete\Core\Validation\CSRF\Token;
use Symfony\Component\HttpFoundation\Response;
use TackTack\TwoFactor\Service\EnrollmentException;
use TackTack\TwoFactor\Service\EnrollmentService;
use TackTack\TwoFactor\Service\PolicyResolver;
use TackTack\TwoFactor\Service\RememberCookie;
use TackTack\TwoFactor\Service\SessionState;
use TackTack\TwoFactor\Service\UserState;

/**
 * /ccm/2fa/enroll — enrôlement forcé (docs/paquet-2fa.md §3.5).
 *
 * Règle générale du §3.3 : la liste blanche du middleware ouvre /ccm/2fa/* à tous les
 * états, donc ce contrôleur recalcule l'état en GET comme en POST, avant toute autre
 * action, et n'accepte que « enroll_required ».
 */
class Enrollment extends Controller
{
    public const TOKEN = 'tacktack_2fa_enroll';

    protected $viewPath = '/two_factor/enroll';

    protected $state;
    protected $enrollment;
    protected $remember;

    public function __construct(UserState $state, EnrollmentService $enrollment, RememberCookie $remember)
    {
        parent::__construct();
        $this->state = $state;
        $this->enrollment = $enrollment;
        $this->remember = $remember;
        $this->setTheme(VIEW_CORE_THEME);
        $this->view->setPackageHandle('tacktack_2fa');
    }

    public function view(): Response
    {
        if ($redirect = $this->guard()) {
            return $redirect;
        }

        return $this->showForm(null);
    }

    public function confirm(): Response
    {
        if ($redirect = $this->guard()) {
            return $redirect;
        }

        /** @var Token $token */
        $token = $this->app->make('token');
        if (!$token->validate(self::TOKEN)) {
            return $this->showForm($token->getErrorMessage());
        }

        $user = $this->app->make(User::class);
        try {
            $codes = $this->enrollment->confirm($user, (string) $this->request->request->get('code', ''));
        } catch (EnrollmentException $e) {
            return $this->showForm($e->getMessage());
        }

        $this->remember->restore($user);
        $this->setViewPath('/two_factor/recovery_codes');
        $this->view->setPackageHandle('tacktack_2fa');
        $this->set('codes', $codes);
        $this->set('continueUrl', (string) $this->app->make('url/manager')->resolve(['/']));

        return $this->render();
    }

    /**
     * @return Response|null une redirection si l'état n'est pas « enroll_required »
     */
    protected function guard(): ?Response
    {
        $user = $this->app->make(User::class);
        if (!$user->isRegistered()) {
            return new RedirectResponse((string) $this->app->make('url/manager')->resolve(['/login']));
        }

        // Session ouverte par le super utilisateur (§3.3.1) : rien à vérifier ni à enrôler ici.
        if ($this->sessionState()->isImpersonating((int) $user->getUserID())) {
            return new RedirectResponse((string) $this->app->make('url/manager')->resolve(['/']));
        }

        $state = $this->state->resolve($user);
        if ($state === PolicyResolver::ENROLL_REQUIRED) {
            return null;
        }

        $target = $state === PolicyResolver::PENDING ? '/ccm/2fa/challenge' : '/';

        return new RedirectResponse((string) $this->app->make('url/manager')->resolve([$target]));
    }

    protected function sessionState(): SessionState
    {
        return $this->app->make(SessionState::class);
    }

    protected function showForm(?string $error): Response
    {
        $user = $this->app->make(User::class);
        $data = $this->enrollment->begin($user);
        $this->set('secret', $data['groupedSecret']);
        $this->set('qrSvg', $data['qrSvg']);
        $this->set('error', $error);
        $this->set('formAction', (string) $this->app->make('url/manager')->resolve(['/ccm/2fa/enroll/confirm']));
        $this->set('tokenName', self::TOKEN);

        return $this->render();
    }

    protected function render(): Response
    {
        $view = $this->getViewObject();
        $response = new Response($view->render());
        // Secret et codes de secours : jamais de mise en cache.
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }
}
