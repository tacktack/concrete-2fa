<?php

use TackTack\TwoFactor\Http\SudoIntent;

const SUPER = 1;

it('arme l\'intention seulement pour un POST au jeton valide du super utilisateur vérifié, sur l\'action sudo', function () {
    // cas nominal
    expect(SudoIntent::shouldArm('POST', 7, SUPER, SUPER, true, true))->toBeTrue();
    expect(SudoIntent::shouldArm('post', 7, SUPER, SUPER, true, true))->toBeTrue();
    // GET (lien externe, prélecture du navigateur) : rien
    expect(SudoIntent::shouldArm('GET', 7, SUPER, SUPER, true, true))->toBeFalse();
    expect(SudoIntent::shouldArm('HEAD', 7, SUPER, SUPER, true, true))->toBeFalse();
    // jeton absent ou refusé : le cœur n'exécutera pas l'action
    expect(SudoIntent::shouldArm('POST', 7, SUPER, SUPER, true, false))->toBeFalse();
    // ce n'est pas l'action sudo
    expect(SudoIntent::shouldArm('POST', null, SUPER, SUPER, true, true))->toBeFalse();
    // un autre administrateur
    expect(SudoIntent::shouldArm('POST', 7, 3, SUPER, true, true))->toBeFalse();
    // le super utilisateur pas encore vérifié (délai de grâce, pas de code)
    expect(SudoIntent::shouldArm('POST', 7, SUPER, SUPER, false, true))->toBeFalse();
});

it('sans intention, rien à faire', function () {
    expect(SudoIntent::evaluate(null, 7, 1000, SUPER))->toBe(SudoIntent::NONE);
});

it('une intention périmée est effacée, même si la session a basculé vers la cible', function () {
    $intent = ['origin' => SUPER, 'target' => 7, 'at' => 1000];
    expect(SudoIntent::evaluate($intent, 7, 1031, SUPER))->toBe(SudoIntent::CLEAR);
    expect(SudoIntent::evaluate($intent, SUPER, 1031, SUPER))->toBe(SudoIntent::CLEAR);
});

it('tant que la session est celle de l\'origine, l\'intention est gardée', function () {
    $intent = ['origin' => SUPER, 'target' => 7, 'at' => 1000];
    expect(SudoIntent::evaluate($intent, SUPER, 1010, SUPER))->toBe(SudoIntent::KEEP);
});

it('accorde l\'exemption quand la session devient la cible demandée, dans la fenêtre', function () {
    $intent = ['origin' => SUPER, 'target' => 7, 'at' => 1000];
    expect(SudoIntent::evaluate($intent, 7, 1000, SUPER))->toBe(SudoIntent::GRANT);
    expect(SudoIntent::evaluate($intent, 7, 1030, SUPER))->toBe(SudoIntent::GRANT);
});

it('refuse et efface si la session devient un autre utilisateur que la cible', function () {
    $intent = ['origin' => SUPER, 'target' => 7, 'at' => 1000];
    expect(SudoIntent::evaluate($intent, 8, 1005, SUPER))->toBe(SudoIntent::CLEAR);
});

it('refuse une intention dont l\'origine n\'est pas le super utilisateur', function () {
    $intent = ['origin' => 3, 'target' => 7, 'at' => 1000];
    expect(SudoIntent::evaluate($intent, 7, 1005, SUPER))->toBe(SudoIntent::CLEAR);
});

it('le détournement décrit par la revue ne passe plus : sudo rejeté, puis un autre utilisateur se connecte', function () {
    // 1. Un POST sans jeton valide n'arme rien : il n'y a donc pas d'intention à détourner.
    expect(SudoIntent::shouldArm('POST', 7, SUPER, SUPER, true, false))->toBeFalse();
    // 2. Même armée (jeton valide mais cible inexistante par exemple), l'intention n'honore que la
    //    cible demandée : X ≠ cible → refus.
    $intent = ['origin' => SUPER, 'target' => 99, 'at' => 1000];
    expect(SudoIntent::evaluate($intent, 7, 1005, SUPER))->toBe(SudoIntent::CLEAR);
    // 3. Passé 30 s, plus rien ne vaut.
    expect(SudoIntent::evaluate($intent, 99, 1100, SUPER))->toBe(SudoIntent::CLEAR);
});
