<?php

defined('C5_EXECUTE') or die('Access Denied.');

$subject = t('Two-factor authentication disabled on %s', $siteName);
$bodyHTML = '<p>' . h(t('Two-factor authentication was just disabled on your account at %s.', $siteName)) . '</p>'
    . '<p>' . h(t('If you did not do this, contact the site administrator immediately.')) . '</p>';
$body = t('Two-factor authentication was just disabled on your account at %s.', $siteName) . "\n\n"
    . t('If you did not do this, contact the site administrator immediately.') . "\n";
