<?php

namespace TackTack\TwoFactor\Http;

use Concrete\Core\Application\Application;
use Concrete\Core\Http\Middleware\DelegateInterface;
use Concrete\Core\Http\Middleware\MiddlewareInterface;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerFactory;
use Concrete\Core\Routing\RedirectResponse;
use Concrete\Core\Session\SessionValidator;
use Concrete\Core\User\PostLoginLocation;
use Concrete\Core\User\User;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use TackTack\TwoFactor\Service\PolicyResolver;
use TackTack\TwoFactor\Service\RememberCookie;
use TackTack\TwoFactor\Service\SessionState;
use TackTack\TwoFactor\Service\UserState;

/**
 * Point de contrôle unique.
 *
 * Échec fermé : un utilisateur soumis à la 2FA sans marqueur « vérifié » en session
 * n'accède à rien d'autre que l'écran de code et la déconnexion. Pas de try/catch
 * « laisser passer » : une exception pour un utilisateur enregistré finit en erreur 500,
 * jamais en contenu servi.
 */
class TwoFactorMiddleware implements MiddlewareInterface
{
    public const PRIORITY = 20;

    /** @var Application */
    protected $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function process(Request $request, DelegateInterface $frame)
    {
        // 1. Pas de session active : rien à contrôler, et on ne démarre pas de session.
        if (!$this->app->make(SessionValidator::class)->hasActiveSession()) {
            return $frame->next($request);
        }

        // 2. Reconnexion par le cookie « rester connecté » : sans elle, ce cookie
        // connecterait l'utilisateur après ce middleware, hors de tout contrôle. Reproduit
        // DefaultDispatcher::getEarlyDispatchResponse().
        $session = $this->app['session'];
        if (!$session->has('uID')) {
            User::verifyAuthTypeCookie();
        }

        // 3. Utilisateur non enregistré : laisser passer.
        if (!($session->get('uID') > 0)) {
            return $frame->next($request);
        }
        $user = $this->app->make(User::class);
        if (!$user->isRegistered()) {
            return $frame->next($request);
        }

        $uID = (int) $user->getUserID();
        $sessionState = $this->app->make(SessionState::class);

        // Intention notée avant l'action « Se connecter en tant que », pilotée par SudoIntent.
        $intent = $sessionState->peekSudoPending();
        switch (SudoIntent::evaluate($intent, $uID, time(), $this->superUserID())) {
            case SudoIntent::CLEAR:
                $sessionState->clearSudoPending();
                break;
            case SudoIntent::GRANT:
                $sessionState->clearSudoPending();
                $this->grantImpersonation($uID, (int) $intent['origin']);

                return $frame->next($request);
        }

        // Session ouverte par le super utilisateur via « Se connecter en tant que » :
        // aucun contrôle, et aucun état calculé (resolve() peut démarrer un délai de grâce, ce
        // qu'un passage de support ne doit pas faire à la place de l'utilisateur).
        if ($sessionState->isImpersonating($uID)) {
            return $frame->next($request);
        }

        // 4 et 5. État.
        $state = $this->app->make(UserState::class)->resolve($user);
        if ($state === PolicyResolver::PENDING) {
            $sessionState->touchPendingSince($uID);
        }

        // Le super utilisateur déjà vérifié lance l'action « Se connecter en tant que » : on note
        // l'intention avant la requête, mais seulement pour un POST portant un jeton CSRF valide
        // (le cœur exécutera alors l'action). Un GET venu d'ailleurs, une requête au jeton refusé ou
        // une simple prélecture du navigateur n'arment rien.
        if ($state === PolicyResolver::VERIFIED && $uID === $this->superUserID()) {
            $signInAs = SudoRequest::targetFromPath($request->getPathInfo());
            if (SudoIntent::shouldArm($request->getMethod(), $signInAs, $uID, $this->superUserID(), true, $this->hasValidToken($request))) {
                $sessionState->armSudo($uID, (int) $signInAs);
            }
        }

        if (in_array($state, [PolicyResolver::NOT_REQUIRED, PolicyResolver::VERIFIED, PolicyResolver::GRACE], true)) {
            return $frame->next($request);
        }

        // 7 (avancé avant la liste blanche) : le cookie « rester connecté » est supprimé dès
        // qu'on constate l'étape 2FA, y compris sur une page en liste blanche. Ainsi aucun
        // chemin (accès direct à /ccm/2fa/challenge, fermeture du navigateur) ne laisse un
        // cookie capable de reconnecter sans code.
        $this->app->make(RememberCookie::class)->suspend($uID);

        // 6. Liste blanche.
        if (PathWhitelist::matches($request->getPathInfo())) {
            return $frame->next($request);
        }

        $target = $this->app->make('url/manager')->resolve([
            $state === PolicyResolver::PENDING ? '/ccm/2fa/challenge' : '/ccm/2fa/enroll',
        ]);

        // 8. Requête AJAX / JSON.
        if ($request->isXmlHttpRequest() || strpos((string) $request->headers->get('Accept'), 'application/json') !== false) {
            return new JsonResponse(['error' => 'two_factor_required', 'redirect' => (string) $target], 401);
        }

        // 9. Mémoriser la destination, sans écraser celle que la page de connexion a posée.
        if ($request->isMethod('GET')) {
            $this->rememberLocation($request);
        }

        // 10.
        return new RedirectResponse((string) $target);
    }

    /**
     * Jeton CSRF du cœur (action par défaut, comme l'action sudo) valide pour cette session.
     */
    protected function hasValidToken(Request $request): bool
    {
        $token = $request->request->get('ccm_token');

        return is_string($token) && $token !== '' && $this->app->make('token')->validate('', $token);
    }

    protected function superUserID(): int
    {
        return (int) USER_SUPER_ID;
    }

    /**
     * Pose la marque d'exemption et journalise quand un contrôle est réellement sauté. Aucune
     * notification.
     */
    protected function grantImpersonation(int $target, int $origin): void
    {
        $this->app->make(SessionState::class)->setImpersonation($target, $origin);

        // Lecture seule : pas de resolve(), qui écrirait en base pour la cible.
        $state = $this->app->make(UserState::class);
        $credential = $state->getCredential($target);
        $targetUser = User::getByUserID($target);
        $skipped = ($credential !== null && $credential->isConfirmed())
            || ($targetUser && $state->isRequired($targetUser));
        if ($skipped) {
            $this->app->make(LoggerFactory::class)->createLogger(Channels::CHANNEL_AUTHENTICATION)
                ->warning(sprintf('2FA : session ouverte en tant que l\'utilisateur %d par le super utilisateur, étape 2FA sautée.', $target));
        }
    }

    protected function rememberLocation(Request $request): void
    {
        $path = $request->getPathInfo();
        if (strncmp($path, '/login', 6) === 0 || strncmp($path, '/ccm/', 5) === 0) {
            return;
        }
        $location = $this->app->make(PostLoginLocation::class);
        if ($location->getSessionPostLoginUrl() !== '') {
            return;
        }
        $uri = $request->getRequestUri();
        if (SafeLocation::isSafe($uri)) {
            $location->setSessionPostLoginUrl($uri);
        }
    }
}
