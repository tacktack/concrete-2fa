<?php

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * @var string $formAction
 * @var string $switchUrl
 * @var string $logoutUrl
 * @var string $tokenName
 * @var bool   $recovery
 */
$token = app('token');
?>
<div class="container py-5" style="max-width: 28rem">
    <h1 class="h3 mb-3"><?= t('Two-factor authentication') ?></h1>
    <p>
        <?php if ($recovery) { ?>
            <?= t('Enter one of your recovery codes. Each code can be used only once.') ?>
        <?php } else { ?>
            <?= t('Enter the 6-digit code from your authenticator app.') ?>
        <?php } ?>
    </p>
    <form method="post" action="<?= h($formAction) ?>" autocomplete="off">
        <?php $token->output($tokenName); ?>
        <div class="mb-3">
            <label for="tacktack-2fa-code" class="form-label"><?= $recovery ? t('Recovery code') : t('Authentication code') ?></label>
            <?php if ($recovery) { ?>
                <input type="text" id="tacktack-2fa-code" name="code" class="form-control" inputmode="text"
                       autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="12" required autofocus>
            <?php } else { ?>
                <input type="text" id="tacktack-2fa-code" name="code" class="form-control" inputmode="numeric"
                       autocomplete="one-time-code" maxlength="7" required autofocus>
            <?php } ?>
        </div>
        <button type="submit" class="btn btn-primary"><?= t('Verify') ?></button>
        <a class="btn btn-link" href="<?= h($logoutUrl) ?>"><?= t('Sign out') ?></a>
    </form>
    <p class="mt-3">
        <a href="<?= h($switchUrl) ?>"><?= $recovery ? t('Use the code from my authenticator app') : t('Use a recovery code') ?></a>
    </p>
</div>
