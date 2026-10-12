<?php

defined('C5_EXECUTE') or die('Access Denied.');

$subject = t('New recovery codes generated on %s', $siteName);
$bodyHTML = '<p>' . h(t('New two-factor recovery codes were just generated for your account at %s. The previous codes no longer work.', $siteName)) . '</p>'
    . '<p>' . h(t('If you did not do this, contact the site administrator immediately.')) . '</p>';
$body = t('New two-factor recovery codes were just generated for your account at %s. The previous codes no longer work.', $siteName) . "\n\n"
    . t('If you did not do this, contact the site administrator immediately.') . "\n";
