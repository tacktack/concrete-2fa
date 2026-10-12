<?php

use TackTack\TwoFactor\Service\TotpService;

beforeEach(function () {
    $this->totp = new TotpService();
    $this->secret = $this->totp->generateSecret();
    $this->now = 55000000;
});

it('génère un secret de 160 bits (32 caractères base32)', function () {
    expect($this->secret)->toMatch('/^[A-Z2-7]{32}$/');
});

it('accepte le code du pas courant et renvoie ce pas', function () {
    $code = $this->totp->codeAt($this->secret, $this->now);
    expect($this->totp->verify($this->secret, $code, null, $this->now))->toBe($this->now);
});

it('accepte un code à ±1 pas', function () {
    foreach ([-1, 1] as $delta) {
        $code = $this->totp->codeAt($this->secret, $this->now + $delta);
        expect($this->totp->verify($this->secret, $code, null, $this->now))->toBe($this->now + $delta);
    }
});

it('refuse un code à ±2 pas', function () {
    foreach ([-2, 2] as $delta) {
        $code = $this->totp->codeAt($this->secret, $this->now + $delta);
        expect($this->totp->verify($this->secret, $code, null, $this->now))->toBeNull();
    }
});

it('refuse le rejeu d\'un code déjà accepté et de tout pas antérieur', function () {
    $code = $this->totp->codeAt($this->secret, $this->now);
    $step = $this->totp->verify($this->secret, $code, null, $this->now);

    expect($this->totp->verify($this->secret, $code, $step, $this->now))->toBeNull();

    $older = $this->totp->codeAt($this->secret, $this->now - 1);
    expect($this->totp->verify($this->secret, $older, $step, $this->now))->toBeNull();
});

it('refuse les saisies mal formées sans lever d\'exception', function () {
    foreach (['', 'abcdef', '12345', '1234567', '12 34'] as $bad) {
        expect($this->totp->verify($this->secret, $bad, null, $this->now))->toBeNull();
    }
});

it('tolère les espaces dans la saisie', function () {
    $code = $this->totp->codeAt($this->secret, $this->now);
    $spaced = substr($code, 0, 3) . ' ' . substr($code, 3);
    expect($this->totp->verify($this->secret, $spaced, null, $this->now))->toBe($this->now);
});

it('refuse proprement un secret invalide', function () {
    expect($this->totp->verify('!!!', '123456', null, $this->now))->toBeNull();
});

it('construit une URI otpauth encodée', function () {
    $uri = $this->totp->provisioningUri('Example & Co', 'a@b.fr', $this->secret);
    expect($uri)->toStartWith('otpauth://totp/')->toContain('issuer=Example');
});
