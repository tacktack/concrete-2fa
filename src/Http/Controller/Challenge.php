<?php

namespace TackTack\TwoFactor\Http\Controller;

use Concrete\Core\Controller\Controller;
use Concrete\Core\Site\Service as SiteService;
use Concrete\Core\User\PostLoginLocation;
use Concrete\Core\User\User;
use Symfony\Component\HttpFoundation\Response;
use TackTack\TwoFactor\Service\ChallengeService;
use TackTack\TwoFactor\Service\Notifier;
use TackTack\TwoFactor\Service\PolicyResolver;
use TackTack\TwoFactor\Service\RememberCookie;
use TackTack\TwoFactor\Service\SessionState;
use TackTack\TwoFactor\Service\UserState;

/**
 * /ccm/2fa/challenge — écran de code (docs/paquet-2fa.md §3.4).
 *
 * Ordre figé du POST : jeton CSRF, état « pending », délai de 5 minutes, verrou / IP,
 * vérification. Les messages d'erreur ne disent jamais si c'est le code, le verrou ou la
 * configuration qui a échoué, sauf le délai expiré.
 */
class Challenge extends Controller
{
    use RedirectsToPaths;

    public const TOKEN = 'tacktack_2fa_challenge';
    public const TIMEOUT_SECONDS = 300;

    protected $viewPath = '/two_factor/challenge';

    protected $state;
    protected $session;
    protected $challenge;
    protected $notifier;
    protected $sites;
    protected $remember;

    public function __construct(UserState $state, SessionState $session, ChallengeService $challenge, Notifier $notifier, SiteService $sites, RememberCookie $remember)
    {
        parent::__construct();
        $this->state = $state;
        $this->session = $session;
        $this->challenge = $challenge;
        $this->notifier = $notifier;
        $this->sites = $sites;
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

    public function submit(): Response
    {
        $token = $this->app->make('token');
        $user = $this->app->make(User::class);
        if (!$user->isRegistered()) {
            return $this->to('/login');
        }

        // 1. Jeton CSRF, avant tout le reste.
        if (!$token->validate(self::TOKEN)) {
            return $this->guard() ?: $this->showForm(t('The form could not be validated. Please try again.'));
        }

        // 2. Seul l'état « pending » est accepté.
        if ($redirect = $this->guard()) {
            return $redirect;
        }
        $uID = (int) $user->getUserID();

        // 3. Délai de l'étape 2FA. Un marqueur absent vaut « expiré » (échec fermé).
        $since = $this->session->getPendingSince($uID);
        if ($since === null || time() - $since > self::TIMEOUT_SECONDS) {
            return $this->logoutTo('/login/session_invalidated');
        }

        // 4 et 5. Verrou, IP, vérification.
        $result = $this->challenge->attempt($uID, (string) $this->request->request->get('code', ''));
        switch ($result) {
            case ChallengeService::JUST_LOCKED:
                return $this->logoutTo('/login');
            case ChallengeService::LOCKED:
            case ChallengeService::FAILED:
                return $this->showForm(t('The code is not valid, or verification is temporarily unavailable.'));
        }

        // Succès.
        $this->session->regenerate();
        $this->session->markVerified($uID);
        $this->session->clearPendingSince();
        $this->remember->restore($user);

        if ($result === ChallengeService::OK_RECOVERY) {
            $email = (string) $user->getUserInfoObject()->getUserEmail();
            if ($email !== '') {
                $site = $this->sites->getSite();
                $this->notifier->recoveryCodeUsed($email, $site ? (string) $site->getSiteName() : 'Concrete', (int) $this->challenge->getRemainingRecoveryCodes());
            }
        }

        return $this->app->make(PostLoginLocation::class)->getPostLoginRedirectResponse(true);
    }

    /**
     * Règle générale du §3.3 : l'état est recalculé ici, en GET comme en POST.
     *
     * @return Response|null une redirection si l'état n'est pas « pending »
     */
    protected function guard(): ?Response
    {
        $user = $this->app->make(User::class);
        if (!$user->isRegistered()) {
            return $this->to('/login');
        }

        // Session ouverte par le super utilisateur (§3.3.1) : rien à vérifier ni à enrôler ici.
        if ($this->sessionState()->isImpersonating((int) $user->getUserID())) {
            return $this->to('/');
        }

        $state = $this->state->resolve($user);
        if ($state === PolicyResolver::PENDING) {
            // Le middleware pose déjà ce marqueur ; ceci couvre un appel sans lui.
            $this->session->touchPendingSince((int) $user->getUserID());

            return null;
        }

        return $this->to($state === PolicyResolver::ENROLL_REQUIRED ? '/ccm/2fa/enroll' : '/');
    }

    protected function sessionState(): SessionState
    {
        return $this->session;
    }

    protected function showForm(?string $error): Response
    {
        // « Utiliser un code de secours » (§3.4) : même formulaire, saisie texte au lieu du pavé
        // numérique. Le serveur reconnaît le type de code à sa forme, pas à cette variante.
        $recovery = (bool) $this->request->query->get('recovery');
        $challengeUrl = (string) $this->app->make('url/manager')->resolve(['/ccm/2fa/challenge']);
        $this->set('error', $error);
        $this->set('recovery', $recovery);
        $this->set('formAction', $recovery ? $challengeUrl . '?recovery=1' : $challengeUrl);
        $this->set('switchUrl', $recovery ? $challengeUrl : $challengeUrl . '?recovery=1');
        $this->set('logoutUrl', (string) $this->app->make('url/manager')->resolve(['/login', 'do_logout', $this->app->make('token')->generate('do_logout')]));
        $this->set('tokenName', self::TOKEN);

        $response = new Response($this->getViewObject()->render());
        $response->headers->set('Cache-Control', 'no-store, private');

        return $response;
    }

    /**
     * Déconnexion puis redirection. Le thème Oli n'affiche pas les messages flash : le délai
     * expiré passe par /login/session_invalidated, dont le message est rendu par le cœur ;
     * le verrou reste silencieux (message générique, §3.4) et l'écran de code le redit à la
     * reconnexion.
     */
    protected function logoutTo(string $path): Response
    {
        $this->app->make(User::class)->logout();

        return $this->to($path);
    }
}
