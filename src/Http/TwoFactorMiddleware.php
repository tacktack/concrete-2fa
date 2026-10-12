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
 * Point de contrôle unique (docs/paquet-2fa.md §2 décisions #1 et #2, §3.3).
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
        // connecterait l'utilisateur après ce middleware, hors de tout contrôle (§1 constat 2
        // et 3). Reproduit DefaultDispatcher::getEarlyDispatchResponse().
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

        // Session ouverte par le super utilisateur via « Se connecter en tant que » (§3.3.1) :
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

        // « Se connecter en tant que » par le super utilisateur déjà vérifié : on observe le
        // résultat de la requête, on n'arme rien à l'avance (§3.3.1).
        if ($state === PolicyResolver::VERIFIED && $uID === $this->superUserID()) {
            $signInAs = SudoRequest::targetFromPath($request->getPathInfo());
            if ($signInAs !== null) {
                $response = $frame->next($request);
                $this->afterSignInAs($uID, $signInAs);

                return $response;
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

    protected function superUserID(): int
    {
        return (int) USER_SUPER_ID;
    }

    /**
     * Après la requête « sudo » : si la session est bien devenue celle de la cible, pose la marque
     * d'exemption et journalise quand un contrôle est réellement sauté. Aucune notification (§3.3.1).
     */
    protected function afterSignInAs(int $before, int $target): void
    {
        $after = (int) $this->app['session']->get('uID');
        if (!SudoRequest::isExemptSignIn($this->superUserID(), $before, true, $after, $target)) {
            return;
        }

        $this->app->make(SessionState::class)->setImpersonation($after, $before);

        // Lecture seule : pas de resolve(), qui écrirait en base pour la cible.
        $state = $this->app->make(UserState::class);
        $credential = $state->getCredential($after);
        $targetUser = User::getByUserID($after);
        $skipped = ($credential !== null && $credential->isConfirmed())
            || ($targetUser && $state->isRequired($targetUser));
        if ($skipped) {
            $this->app->make(LoggerFactory::class)->createLogger(Channels::CHANNEL_AUTHENTICATION)
                ->warning(sprintf('2FA : session ouverte en tant que l\'utilisateur %d par le super utilisateur, étape 2FA sautée.', $after));
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
