<?php

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * @var string      $secret     secret groupé par 4 caractères
 * @var string      $qrSvg      SVG inline généré côté serveur
 * @var string      $formAction
 * @var string      $tokenName
 */
$token = app('token');
?>
<p><?= t('Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password…), then enter the 6-digit code it shows.') ?></p>

<div class="mb-3" aria-label="<?= h(t('QR code')) ?>"><?= $qrSvg /* SVG produit par bacon-qr-code, aucune donnée utilisateur */ ?></div>

<p>
    <?= t("Can't scan? Enter this key manually:") ?><br>
    <code><?= h($secret) ?></code>
</p>

<form method="post" action="<?= h($formAction) ?>" autocomplete="off">
    <?php $token->output($tokenName); ?>
    <div class="mb-3">
        <label for="tacktack-2fa-code" class="form-label"><?= t('Authentication code') ?></label>
        <input type="text" id="tacktack-2fa-code" name="code" class="form-control" inputmode="numeric"
               autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="7" required autofocus>
    </div>
    <button type="submit" class="btn btn-primary"><?= t('Enable two-factor authentication') ?></button>
</form>
