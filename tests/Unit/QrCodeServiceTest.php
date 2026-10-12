<?php

use TackTack\TwoFactor\Service\QrCodeService;

it('produit un SVG inline sans prologue XML ni référence externe', function () {
    $svg = (new QrCodeService())->svg('otpauth://totp/Oli:a@b.fr?secret=JBSWY3DPEHPK3PXP&issuer=Oli');

    expect($svg)->toStartWith('<svg');
    expect($svg)->not->toContain('<?xml');
    expect(preg_replace('#http://www\.w3\.org/\d+/svg#', '', $svg))->not->toMatch('#https?://#');
});
