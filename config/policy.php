<?php

defined('C5_EXECUTE') or die('Access Denied.');

/*
 * Valeurs par défaut de la politique 2FA (tacktack_2fa::policy.*).
 * Le Dashboard (/dashboard/system/registration/two_factor, étape 7) enregistre ses
 * réglages via Config::save('tacktack_2fa::policy.*') ; ce fichier ne fournit que les
 * valeurs par défaut tant qu'aucune valeur n'a été enregistrée en base.
 *
 * ADMIN_GROUP_ID est une constante du cœur (bootstrap/configure.php), stable, et non
 * un identifiant recréé par ce paquet : voir §2 décision 10 de docs/paquet-2fa.md.
 */

return [
    // Groupes pour lesquels la 2FA est obligatoire.
    'groups' => [ADMIN_GROUP_ID],

    // Délai de grâce, en jours, avant qu'un utilisateur concerné ne soit forcé
    // à s'enrôler (voir §3.2 de docs/paquet-2fa.md).
    'grace_days' => 7,

    // Nom affiché dans l'application d'authentification (issuer de l'URI otpauth://).
    // null = nom du site (Site::getSiteName()) résolu au moment de l'enrôlement.
    'issuer' => null,
];
