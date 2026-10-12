<?php

defined('C5_EXECUTE') or die('Access Denied.');

$subject = t('Two-factor authentication reset on %s', $siteName);
$bodyHTML = '<p>' . h(t('An administrator reset the two-factor authentication of your account at %s.', $siteName)) . '</p>'
    . '<p>' . h(t('If two-factor authentication is required for your account, you will be asked to set it up again the next time you sign in.')) . '</p>'
    . '<p>' . h(t('If you did not expect this, contact the site administrator.')) . '</p>';
$body = t('An administrator reset the two-factor authentication of your account at %s.', $siteName) . "\n\n"
    . t('If two-factor authentication is required for your account, you will be asked to set it up again the next time you sign in.') . "\n\n"
    . t('If you did not expect this, contact the site administrator.') . "\n";
