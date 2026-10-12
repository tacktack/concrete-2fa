<?php

use TackTack\TwoFactor\Http\SudoRequest;

it('reconnaît exactement l\'action sudo du Dashboard', function (string $path, int $expected) {
    expect(SudoRequest::targetFromPath($path))->toBe($expected);
})->with([
    ['/dashboard/users/search/update_status/sudo/7', 7],
    ['/index.php/dashboard/users/search/update_status/sudo/42', 42],
    ['/dashboard/users/search/update_status/sudo/7/', 7],
    ['/dashboard/users/search/update_status/sudo/1234567890', 1234567890],
]);

it('refuse tout autre chemin, y compris les chemins piégés', function (string $path) {
    expect(SudoRequest::targetFromPath($path))->toBeNull();
})->with([
    '',
    '/',
    '/dashboard/users/search/update_status/sudo/',
    '/dashboard/users/search/update_status/sudo/abc',
    '/dashboard/users/search/update_status/sudo/7x',
    '/dashboard/users/search/update_status/sudo/-1',
    '/dashboard/users/search/update_status/sudo/12345678901',
    '/dashboard/users/search/update_status/activate/7',
    '/dashboard/users/search/update_status/sudo/7/extra',
    '/dashboard/users/search/sudo/7',
    '/x/dashboard/users/search/update_status/sudo/7',
    '/dashboard/users/search/update_status/sudo/../sudo/7',
    '/dashboard/users/search/update_status/sudo/7%2F..%2F8',
    '//dashboard/users/search/update_status/sudo/7',
    '/dashboard/users/search/update_status/sudo/7\\8',
    "/dashboard/users/search/update_status/sudo/7\r\n",
    'dashboard/users/search/update_status/sudo/7',
]);

it('décode une seule fois : le chemin décodé est celui qui compte, le double encodage est refusé', function () {
    expect(SudoRequest::targetFromPath('/dashboard/users/search/update_status/sudo/%37'))->toBe(7);
    expect(SudoRequest::targetFromPath('/dashboard%2Fusers/search/update_status/sudo/7'))->toBe(7);
    expect(SudoRequest::targetFromPath('/dashboard/users/search/update_status/sudo/%2537'))->toBeNull();
    expect(SudoRequest::targetFromPath('/dashboard%252Fusers/search/update_status/sudo/7'))->toBeNull();
});

it('confirme seulement une intention du super utilisateur vers la cible demandée', function () {
    // origine = super utilisateur, la session est devenue la cible demandée
    expect(SudoRequest::isExemptSignIn(1, 1, 7, 7))->toBeTrue();
    // l'origine n'est pas le super utilisateur
    expect(SudoRequest::isExemptSignIn(1, 3, 7, 7))->toBeFalse();
    // la session n'a pas changé
    expect(SudoRequest::isExemptSignIn(1, 1, 1, 7))->toBeFalse();
    // la session est devenue quelqu'un d'autre que la cible demandée
    expect(SudoRequest::isExemptSignIn(1, 1, 8, 7))->toBeFalse();
    // pas de cible, pas d'utilisateur
    expect(SudoRequest::isExemptSignIn(1, 1, 7, null))->toBeFalse();
    expect(SudoRequest::isExemptSignIn(1, 1, 0, 0))->toBeFalse();
});

it('isFresh borne la durée de l\'intention', function () {
    expect(SudoRequest::isFresh(1000, 1000, 30))->toBeTrue();
    expect(SudoRequest::isFresh(1000, 1030, 30))->toBeTrue();
    expect(SudoRequest::isFresh(1000, 1031, 30))->toBeFalse();
    expect(SudoRequest::isFresh(1000, 999, 30))->toBeFalse();
});
