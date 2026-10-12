<?php

defined('C5_EXECUTE') or die('Access Denied.');

/** @var Concrete\Core\View\View $view */
?>
<div class="container py-5" style="max-width: 32rem">
    <?php $view->element('recovery_codes', get_defined_vars(), 'tacktack_2fa'); ?>
</div>
