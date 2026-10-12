<?php

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * @var Concrete\Core\View\View $view
 * @var int[]    $selectedGroups
 * @var int      $graceDays
 * @var string   $issuer
 * @var array    $groups
 * @var array    $users
 * @var bool     $canReset
 * @var int      $myID
 * @var bool     $isSuper
 */
$token = app('token');
$statusLabels = [
    'enabled' => t('Enabled'),
    'grace' => t('Grace period'),
    'enroll_required' => t('Must set up'),
];
?>
<form method="post" action="<?= h($view->action('save_settings')) ?>">
    <?php $token->output("tacktack_2fa_settings"); ?>

    <fieldset>
        <legend><?= t('Policy') ?></legend>

        <div class="mb-3">
            <label class="form-label"><?= t('Groups required to use two-factor authentication') ?></label>
            <?php foreach ($groups as $group) { ?>
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="groups[]" id="tf-group-<?= (int) $group['gID'] ?>"
                           value="<?= (int) $group['gID'] ?>" <?= in_array((int) $group['gID'], $selectedGroups, true) ? 'checked' : '' ?>>
                    <label class="form-check-label" for="tf-group-<?= (int) $group['gID'] ?>"><?= h(t($group['gName'])) ?></label>
                </div>
            <?php } ?>
            <div class="form-text"><?= t('The super user is always required. Any user who sets it up voluntarily is then required too.') ?></div>
        </div>

        <div class="mb-3">
            <label class="form-label" for="tf-grace"><?= t('Grace period (days)') ?></label>
            <input class="form-control" type="number" min="0" max="365" id="tf-grace" name="grace_days" value="<?= (int) $graceDays ?>">
            <div class="form-text"><?= t('Time left to set up two-factor authentication before it becomes mandatory. 0 means immediately.') ?></div>
        </div>

        <div class="mb-3">
            <label class="form-label" for="tf-issuer"><?= t('Name shown in authenticator apps') ?></label>
            <input class="form-control" type="text" maxlength="100" id="tf-issuer" name="issuer" value="<?= h($issuer) ?>">
            <div class="form-text"><?= t('Leave empty to use the site name.') ?></div>
        </div>
    </fieldset>

    <div class="ccm-dashboard-form-actions-wrapper">
        <div class="ccm-dashboard-form-actions">
            <button class="float-end btn btn-primary" type="submit"><?= t('Save') ?></button>
        </div>
    </div>
</form>

<h3 class="mt-5"><?= t('Users concerned') ?></h3>
<?php if (!$users) { ?>
    <p class="text-muted"><?= t('No user is concerned yet.') ?></p>
<?php } else { ?>
    <table class="table table-striped align-middle">
        <thead>
            <tr>
                <th><?= t('User') ?></th>
                <th><?= t('Status') ?></th>
                <th><?= t('Enabled on') ?></th>
                <th><?= t('Failed attempts') ?></th>
                <th><?= t('Lockout') ?></th>
                <?php if ($canReset) { ?><th><?= t('Actions') ?></th><?php } ?>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($users as $u) { ?>
                <tr>
                    <td><?= h($u['uName']) ?><br><small class="text-muted"><?= h($u['uEmail']) ?></small></td>
                    <td>
                        <?= h($statusLabels[$u['status']] ?? $u['status']) ?>
                        <?php if ($u['graceEndsAt']) { ?><br><small class="text-muted"><?= t('until %s', h($u['graceEndsAt'])) ?></small><?php } ?>
                    </td>
                    <td><?= $u['enabledAt'] ? h(substr($u['enabledAt'], 0, 10)) : '—' ?></td>
                    <td><?= (int) $u['failedAttempts'] ?></td>
                    <td><?= $u['locked'] ? '<span class="badge bg-danger">' . t('Locked until %s', h($u['lockedUntil'])) . '</span>' : '—' ?></td>
                    <?php if ($canReset) { ?>
                        <td>
                            <?php if ((int) $u['uID'] === $myID) { ?>
                                <small class="text-muted"><?= t('Your account') ?></small>
                            <?php } elseif ((int) $u['uID'] === (int) USER_SUPER_ID && !$isSuper) { ?>
                                <small class="text-muted"><?= t('Super user') ?></small>
                            <?php } else { ?>
                                <form method="post" class="d-flex gap-1 align-items-center flex-wrap" autocomplete="off">
                                    <?php $token->output('tacktack_2fa_admin_action'); ?>
                                    <input type="hidden" name="uID" value="<?= (int) $u['uID'] ?>">
                                    <input type="password" name="password" class="form-control form-control-sm" style="width: 11rem"
                                           placeholder="<?= h(t('Your password')) ?>" aria-label="<?= h(t('Your password')) ?>" autocomplete="current-password" required>
                                    <button type="submit" class="btn btn-sm btn-danger" formaction="<?= h($view->action('reset')) ?>"><?= t('Reset') ?></button>
                                    <?php if ($u['locked'] || $u['failedAttempts'] > 0) { ?>
                                        <button type="submit" class="btn btn-sm btn-secondary" formaction="<?= h($view->action('lift_lock')) ?>"><?= t('Lift lockout') ?></button>
                                    <?php } ?>
                                </form>
                            <?php } ?>
                        </td>
                    <?php } ?>
                </tr>
            <?php } ?>
        </tbody>
    </table>
    <?php if (!$canReset) { ?>
        <p class="text-muted"><?= t('You do not have the permission to reset two-factor authentication.') ?></p>
    <?php } ?>
<?php } ?>
