<?php

use TackTack\TwoFactor\Http\PathWhitelist;

it('autorise /ccm/2fa/* et la déconnexion', function (string $path) {
    expect(PathWhitelist::matches($path))->toBeTrue();
})->with([
    '/ccm/2fa/challenge',
    '/ccm/2fa/enroll/confirm',
    '/index.php/ccm/2fa/challenge',
    '/ccm/2fa/challenge/',
    '/login/logout',
    '/login/logout/abc123',
    '/login/do_logout/abc123',
    '/login/logout_complete',
    '/login/do_logout/1791802909%3A2672477b4',
]);

it('refuse tout le reste, y compris les chemins piégés', function (string $path) {
    expect(PathWhitelist::matches($path))->toBeFalse();
})->with([
    '',
    '/',
    '/dashboard',
    '/index.php/dashboard',
    '/ccm/2faX',
    '/ccm/2fa-evil',
    '/ccm/2fa/../dashboard',
    '/ccm/2fa%2F..%2Fdashboard',
    '/ccm//2fa/challenge',
    '/index.phpx/ccm/2fa/challenge',
    '/login',
    '/login/authenticate/concrete',
    '/login/logoutX',
    '/login/do_logoutX',
    '/account/two_factor',
    'ccm/2fa/challenge',
    '/ccm/2fa%252F..%252Fdashboard',
    '/login/do_logout/..%2F..%2Fdashboard',
    '/ccm/2fa/x%00',
    '/ccm/2fa%5C..%5Cdashboard',
]);
