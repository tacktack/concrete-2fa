<?php

use TackTack\TwoFactor\Service\PolicyResolver;

beforeEach(function () {
    $this->r = new PolicyResolver();
    $this->now = new DateTimeImmutable('2026-10-12 12:00:00');
});

it('not_required : ni concerné ni enrôlé', function () {
    expect($this->r->resolve(5, false, false, null, 7, null, $this->now))->toBe(PolicyResolver::NOT_REQUIRED);
});

it('verified : enrôlé avec marqueur de session pour ce uID', function () {
    $marker = ['uID' => 5, 'at' => 1];
    expect($this->r->resolve(5, true, true, null, 7, $marker, $this->now))->toBe(PolicyResolver::VERIFIED);
});

it('pending : enrôlé sans marqueur', function () {
    expect($this->r->resolve(5, true, true, null, 7, null, $this->now))->toBe(PolicyResolver::PENDING);
});

it('pending : marqueur posé pour un autre uID (« se connecter en tant que »)', function () {
    $marker = ['uID' => 1, 'at' => 1];
    expect($this->r->resolve(5, true, true, null, 7, $marker, $this->now))->toBe(PolicyResolver::PENDING);
});

it('pending même si l\'utilisateur s\'est enrôlé volontairement hors politique', function () {
    expect($this->r->resolve(5, true, false, null, 7, null, $this->now))->toBe(PolicyResolver::PENDING);
});

it('grace : concerné, non enrôlé, délai en cours ou jamais démarré', function () {
    $started = $this->now->modify('-3 days');
    expect($this->r->resolve(5, false, true, $started, 7, null, $this->now))->toBe(PolicyResolver::GRACE);
    expect($this->r->resolve(5, false, true, null, 7, null, $this->now))->toBe(PolicyResolver::GRACE);
});

it('enroll_required : délai de grâce écoulé', function () {
    $started = $this->now->modify('-8 days');
    expect($this->r->resolve(5, false, true, $started, 7, null, $this->now))->toBe(PolicyResolver::ENROLL_REQUIRED);
});

it('enroll_required immédiat si le délai de grâce est de 0 jour', function () {
    expect($this->r->resolve(5, false, true, null, 0, null, $this->now))->toBe(PolicyResolver::ENROLL_REQUIRED);
});

it('un marqueur de session ne suffit pas sans enrôlement', function () {
    $marker = ['uID' => 5, 'at' => 1];
    expect($this->r->resolve(5, false, true, $this->now->modify('-30 days'), 7, $marker, $this->now))
        ->toBe(PolicyResolver::ENROLL_REQUIRED);
});
