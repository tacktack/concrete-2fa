<?php

namespace TackTack\TwoFactor\Routing;

use Concrete\Core\Routing\RouteListInterface;
use Concrete\Core\Routing\Router;
use TackTack\TwoFactor\Http\Controller\Challenge;
use TackTack\TwoFactor\Http\Controller\Enrollment;

class RouteList implements RouteListInterface
{
    public function loadRoutes(Router $router)
    {
        $router->get('/ccm/2fa/challenge', Challenge::class . '::view');
        $router->post('/ccm/2fa/challenge', Challenge::class . '::submit');
        $router->get('/ccm/2fa/enroll', Enrollment::class . '::view');
        $router->post('/ccm/2fa/enroll/confirm', Enrollment::class . '::confirm');
    }
}
