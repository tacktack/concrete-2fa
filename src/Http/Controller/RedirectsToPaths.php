<?php

namespace TackTack\TwoFactor\Http\Controller;

use Concrete\Core\Routing\RedirectResponse;

/**
 * Redirection vers un chemin du site, partagée par les contrôleurs /ccm/2fa/*.
 * Le contrôleur qui l'utilise fournit $this->app.
 */
trait RedirectsToPaths
{
    protected function to(string $path): RedirectResponse
    {
        return new RedirectResponse((string) $this->app->make('url/manager')->resolve([$path]));
    }
}
