<?php

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * @var Concrete\Core\View\View $view
 * @var string                  $mode   'status' | 'enroll' | 'codes'
 */
$token = app('token');
?>
<h2><?= t('Two-factor authentication') ?></h2>

<?php if ($mode === 'codes') { ?>
    <?php $view->element('recovery_codes', ['codes' => $codes, 'continueUrl' => $continueUrl], 'tacktack_2fa'); ?>

<?php } elseif ($mode === 'enroll') { ?>
    <?php $view->element('enroll_form', ['secret' => $secret, 'qrSvg' => $qrSvg, 'formAction' => $formAction, 'tokenName' => $tokenName], 'tacktack_2fa'); ?>

<?php } else { ?>
    <div class="alert alert-success" role="status">
        <?= t('Two-factor authentication is enabled on your account.') ?>
        <?php if ($status['enabledAt']) { ?>
            <?= t('Enabled on %s.', h($status['enabledAt']->format('d/m/Y'))) ?>
        <?php } ?>
    </div>
    <p><?= t2('%d recovery code remaining.', '%d recovery codes remaining.', $status['remaining']) ?></p>

    <h3 class="h5 mt-4"><?= t('Regenerate recovery codes') ?></h3>
    <p><?= t('The previous codes will stop working. Enter the current 6-digit code from your authenticator app. If you just signed in with that code, wait for the next one.') ?></p>
    <form method="post" action="<?= h($regenerateAction) ?>" autocomplete="off">
        <?php $token->output($tokenRegenerate); ?>
        <div class="mb-3">
            <label for="tacktack-2fa-regen-code" class="form-label"><?= t('Authentication code') ?></label>
            <input type="text" id="tacktack-2fa-regen-code" name="code" class="form-control" inputmode="numeric"
                   autocomplete="one-time-code" maxlength="7" required>
        </div>
        <button type="submit" class="btn btn-secondary"><?= t('Regenerate recovery codes') ?></button>
    </form>

    <h3 class="h5 mt-4"><?= t('Disable two-factor authentication') ?></h3>
    <?php if ($status['required']) { ?>
        <p class="text-muted"><?= t('Two-factor authentication is required for your account and cannot be disabled.') ?></p>
    <?php } else { ?>
        <p><?= t('Enter your current password and a code from your authenticator app (or a recovery code).') ?></p>
        <form method="post" action="<?= h($disableAction) ?>" autocomplete="off">
            <?php $token->output($tokenDisable); ?>
            <div class="mb-3">
                <label for="tacktack-2fa-disable-password" class="form-label"><?= t('Current password') ?></label>
                <input type="password" id="tacktack-2fa-disable-password" name="password" class="form-control" autocomplete="current-password" required>
            </div>
            <div class="mb-3">
                <label for="tacktack-2fa-disable-code" class="form-label"><?= t('Authentication code') ?></label>
                <input type="text" id="tacktack-2fa-disable-code" name="code" class="form-control" autocomplete="one-time-code" maxlength="12" required>
            </div>
            <button type="submit" class="btn btn-danger"><?= t('Disable two-factor authentication') ?></button>
        </form>
    <?php } ?>
<?php } ?>
