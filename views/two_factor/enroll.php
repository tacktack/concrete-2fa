<?php

defined('C5_EXECUTE') or die('Access Denied.');

/** @var Concrete\Core\View\View $view */
?>
<div class="container py-5" style="max-width: 32rem">
    <h1 class="h3 mb-3"><?= t('Set up two-factor authentication') ?></h1>
    <?php $view->element('enroll_form', get_defined_vars(), 'tacktack_2fa'); ?>
</div>
