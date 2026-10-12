<?php

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * @var Concrete\Core\View\View $view
 * @var bool                    $enrolled
 * @var string[]|null           $codes
 * @var Concrete\Core\Error\ErrorList\ErrorList|null $error
 */
?>
<h2><?= t('Two-factor authentication') ?></h2>

<?php if (isset($error) && is_object($error) && $error->has()) { ?>
    <div class="alert alert-danger" role="alert"><?= $error->output() ?></div>
<?php } ?>

<?php if (!empty($codes)) { ?>
    <?php $view->element('recovery_codes', ['codes' => $codes, 'continueUrl' => $continueUrl], 'tacktack_2fa'); ?>
<?php } elseif ($enrolled) { ?>
    <div class="alert alert-success" role="status"><?= t('Two-factor authentication is enabled on your account.') ?></div>
<?php } else { ?>
    <?php $view->element('enroll_form', ['secret' => $secret, 'qrSvg' => $qrSvg, 'error' => null, 'formAction' => $formAction, 'tokenName' => $tokenName], 'tacktack_2fa'); ?>
<?php } ?>
