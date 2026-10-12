<?php

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * @var string $formAction
 * @var string $logoutUrl
 * @var string $tokenName
 */
$token = app('token');
?>
<div class="container py-5" style="max-width: 28rem">
    <h1 class="h3 mb-3"><?= t('Two-factor authentication') ?></h1>
    <p><?= t('Enter the 6-digit code from your authenticator app, or one of your recovery codes.') ?></p>
    <form method="post" action="<?= h($formAction) ?>" autocomplete="off">
        <?php $token->output($tokenName); ?>
        <div class="mb-3">
            <label for="tacktack-2fa-code" class="form-label"><?= t('Authentication code') ?></label>
            <input type="text" id="tacktack-2fa-code" name="code" class="form-control" inputmode="numeric"
                   autocomplete="one-time-code" maxlength="12" required autofocus>
        </div>
        <button type="submit" class="btn btn-primary"><?= t('Verify') ?></button>
        <a class="btn btn-link" href="<?= h($logoutUrl) ?>"><?= t('Sign out') ?></a>
    </form>
</div>
