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

it('exige les trois conditions du §3.3.1', function () {
    // uID 1 vérifié, la session devient la cible demandée
    expect(SudoRequest::isExemptSignIn(1, 1, true, 7, 7))->toBeTrue();
    // un autre administrateur n'est pas exempté
    expect(SudoRequest::isExemptSignIn(1, 3, true, 7, 7))->toBeFalse();
    // le super utilisateur non vérifié (grâce, pas de code) n'est pas exempté
    expect(SudoRequest::isExemptSignIn(1, 1, false, 7, 7))->toBeFalse();
    // la session n'a pas changé (jeton refusé, permission absente)
    expect(SudoRequest::isExemptSignIn(1, 1, true, 1, 7))->toBeFalse();
    // la session est devenue quelqu'un d'autre que la cible du chemin
    expect(SudoRequest::isExemptSignIn(1, 1, true, 8, 7))->toBeFalse();
    // la requête n'était pas l'action sudo
    expect(SudoRequest::isExemptSignIn(1, 1, true, 7, null))->toBeFalse();
    // pas d'utilisateur après la requête
    expect(SudoRequest::isExemptSignIn(1, 1, true, 0, 0))->toBeFalse();
});

it('l\'intention notée avant la requête expire', function () {
    expect(SudoRequest::isFresh(1000, 1000))->toBeTrue();
    expect(SudoRequest::isFresh(1000, 1120))->toBeTrue();
    expect(SudoRequest::isFresh(1000, 1121))->toBeFalse();
    expect(SudoRequest::isFresh(1000, 999))->toBeFalse();
});
