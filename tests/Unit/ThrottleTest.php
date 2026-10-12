<?php

use TackTack\TwoFactor\Service\Throttle;

beforeEach(function () {
    $this->t = new Throttle();
    $this->now = new DateTimeImmutable('2026-10-12 12:00:00');
});

it('incrémente sans verrouiller avant le 5e échec', function () {
    $r = $this->t->registerFailure(3, $this->now);
    expect($r['attempts'])->toBe(4)->and($r['locked'])->toBeFalse()->and($r['lockedUntil'])->toBeNull();
});

it('verrouille 15 min au 5e échec et remet le compteur à zéro', function () {
    $r = $this->t->registerFailure(4, $this->now);
    expect($r['locked'])->toBeTrue()->and($r['attempts'])->toBe(0);
    expect($r['lockedUntil'])->toEqual($this->now->modify('+15 minutes'));
});

it('isLocked respecte l\'échéance', function () {
    $until = $this->now->modify('+15 minutes');
    expect($this->t->isLocked($until, $this->now))->toBeTrue();
    expect($this->t->isLocked($until, $this->now->modify('+16 minutes')))->toBeFalse();
    expect($this->t->isLocked(null, $this->now))->toBeFalse();
});
