<?php

use TackTack\TwoFactor\Service\SecretCipher;

afterEach(function () {
    putenv(SecretCipher::ENV_VAR);
});

it('chiffre et déchiffre (aller-retour)', function () {
    $c = new SecretCipher();
    putenv(SecretCipher::ENV_VAR . '=' . $c->generateKey());

    $enc = $c->encrypt('JBSWY3DPEHPK3PXP');
    expect($enc)->not->toContain('JBSWY3DPEHPK3PXP');
    expect($c->decrypt($enc))->toBe('JBSWY3DPEHPK3PXP');
});

it('détecte une clé absente ou invalide', function () {
    $c = new SecretCipher();

    putenv(SecretCipher::ENV_VAR);
    expect($c->isKeyConfigured())->toBeFalse();

    putenv(SecretCipher::ENV_VAR . '=pas-une-cle');
    expect($c->isKeyConfigured())->toBeFalse();

    putenv(SecretCipher::ENV_VAR . '=' . $c->generateKey());
    expect($c->isKeyConfigured())->toBeTrue();
});

it('ne divulgue jamais la valeur de la clé dans les messages d\'erreur', function () {
    putenv(SecretCipher::ENV_VAR . '=valeur-secrete-xyz');
    try {
        (new SecretCipher())->loadKey();
        $this->fail('Exception attendue');
    } catch (RuntimeException $e) {
        expect($e->getMessage())->not->toContain('valeur-secrete-xyz');
    }
});

it('refuse de déchiffrer avec une autre clé', function () {
    $c = new SecretCipher();
    putenv(SecretCipher::ENV_VAR . '=' . $c->generateKey());
    $enc = $c->encrypt('secret');

    putenv(SecretCipher::ENV_VAR . '=' . $c->generateKey());
    expect(fn () => $c->decrypt($enc))->toThrow(RuntimeException::class);
});
