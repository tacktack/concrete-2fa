<?php

defined('C5_EXECUTE') or die('Access Denied.');

$subject = t('A recovery code was used on %s', $siteName);
$bodyHTML = '<p>' . h(t('A two-factor recovery code was just used to sign in to your account at %s.', $siteName)) . '</p>'
    . '<p>' . h(t2('%d recovery code remains.', '%d recovery codes remain.', $remaining)) . '</p>'
    . '<p>' . h(t('If this was not you, contact the site administrator immediately.')) . '</p>';
$body = t('A two-factor recovery code was just used to sign in to your account at %s.', $siteName) . "\n\n"
    . t2('%d recovery code remains.', '%d recovery codes remain.', $remaining) . "\n\n"
    . t('If this was not you, contact the site administrator immediately.') . "\n";
