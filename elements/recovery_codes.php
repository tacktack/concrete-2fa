<?php

defined('C5_EXECUTE') or die('Access Denied.');

/**
 * @var string[] $codes
 * @var string   $continueUrl
 */
?>
<div class="alert alert-success" role="status"><?= t('Two-factor authentication is now enabled.') ?></div>
<h2><?= t('Recovery codes') ?></h2>
<p><?= t('Keep these codes somewhere safe. Each one can be used once if you lose access to your authenticator app. They will not be shown again.') ?></p>
<ul class="list-unstyled font-monospace">
    <?php foreach ($codes as $code) { ?>
        <li><?= h($code) ?></li>
    <?php } ?>
</ul>
<a class="btn btn-primary" href="<?= h($continueUrl) ?>"><?= t('Continue') ?></a>
