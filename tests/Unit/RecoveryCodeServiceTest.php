<?php

use TackTack\TwoFactor\Service\RecoveryCodeService;

beforeEach(function () {
    $this->svc = new RecoveryCodeService();
});

it('génère 10 codes distincts au format xxxx-xxxx', function () {
    $codes = $this->svc->generate();
    expect($codes)->toHaveCount(10);
    expect(array_unique($codes))->toHaveCount(10);
    foreach ($codes as $code) {
        expect($code)->toMatch('/^[a-z2-9]{4}-[a-z2-9]{4}$/');
        expect($code)->not->toMatch('/[01oli]/');
    }
});

it('vérifie un code avec normalisation (casse, tiret, espaces)', function () {
    $hash = $this->svc->hash('abcd-efgh');
    expect($this->svc->verify('abcd-efgh', $hash))->toBeTrue();
    expect($this->svc->verify('ABCD EFGH', $hash))->toBeTrue();
    expect($this->svc->verify(' abcdefgh ', $hash))->toBeTrue();
    expect($this->svc->verify('abcd-efgx', $hash))->toBeFalse();
    expect($this->svc->verify('abcd', $hash))->toBeFalse();
});

it('ne stocke jamais le code en clair dans le hachage', function () {
    $hash = $this->svc->hash('abcd-efgh');
    expect($hash)->not->toContain('abcd');
});

it('distingue un code de secours d\'un code TOTP', function () {
    expect($this->svc->looksLikeRecoveryCode('abcd-efgh'))->toBeTrue();
    expect($this->svc->looksLikeRecoveryCode('123456'))->toBeFalse();
});
