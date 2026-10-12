# concrete-2fa

Double authentification TOTP (Google Authenticator, Authy, 1Password…) pour Concrete CMS 9.
Testée avec **PHP 8.4** et **Concrete CMS 9.5 ou plus récent** (voir « Compatibilité »).

- Codes à usage unique conformes RFC 6238 (SHA-1, 6 chiffres, pas de 30 s, tolérance ±1 pas), rejeu refusé.
- Secret chiffré au repos (defuse/php-encryption) ; la clé vit dans une variable d'environnement, jamais en base.
- QR code généré côté serveur, en SVG : le secret ne part vers aucun service tiers.
- 10 codes de secours à usage unique, hachés, régénérables.
- Politique par groupe, avec délai de grâce ; le super utilisateur est toujours concerné.
- Verrou après 5 échecs (15 min) et bannissement IP (20 échecs en 10 min).
- Contrôle par middleware HTTP, **en échec fermé** : il couvre tous les chemins de connexion (mot de passe,
  OAuth, « rester connecté », « Se connecter en tant que »).
- Pas de « mot de passe d'urgence » : codes de secours, réinitialisation par un administrateur ou ligne de commande.

## Compatibilité

Le paquet fonctionne avec **PHP 8.4** sur **Concrete CMS 9.5 ou plus récent** (version de référence : 9.5.4).
**Dans le doute, utiliser PHP 8.4 et Concrete CMS > 9.4** : c'est la seule combinaison testée. Le contrôleur
du paquet déclare Concrete ≥ 9.0.0 et PHP ≥ 8.1, mais ces versions plus anciennes n'ont pas été vérifiées.
Essayer d'abord sur un environnement de développement avant la production.

## Installation sur un projet Concrete CMS

Le guide ci-dessous suppose un projet géré par Composer (squelette `concretecms/composer`). Le paquet n'est pas
sur Packagist : il faut déclarer son dépôt.

### 1. Déclarer le dépôt et installer le paquet

Dans le `composer.json` du projet :

```json
"repositories": [
  { "type": "vcs", "url": "https://github.com/tacktack/concrete-2fa", "no-api": true }
]
```

`no-api: true` évite que Composer interroge l'API GitHub, qui échoue sans jeton ; le dépôt étant public, aucune
authentification n'est nécessaire. Puis, depuis la racine du projet :

```bash
composer require tacktack/concrete-2fa:^1.0
```

Le paquet doit atterrir dans le dossier des paquets du projet (handle `tacktack_2fa`). C'est automatique si le
projet déclare, comme le squelette `concretecms/composer`, le chemin des paquets Concrete pour `composer/installers` :

```json
"extra": {
  "installer-paths": {
    "public/packages/{$name}": ["type:concrete5-package"]
  }
}
```

Après l'installation, vérifier que le dossier `public/packages/tacktack_2fa/` existe (adapter `public/` si le
projet utilise un autre dossier web).

### 2. Générer la clé de chiffrement — avant l'installation du paquet

**Une clé par site et par environnement** (développement, staging, production), jamais versionnée, jamais celle d'un
autre projet. Les commandes `2fa:*` n'existent qu'une fois le paquet installé : avant, utiliser l'outil fourni par
defuse, depuis la racine du projet :

```bash
php -d display_errors=0 vendor/bin/generate-defuse-key
```

(`display_errors=0` évite que des avertissements de PHP 8.4 s'impriment avec la clé quand on copie le résultat.)
Conserver la clé dans un gestionnaire de mots de passe.

### 3. Mettre la clé à disposition de PHP

La variable s'appelle `TWOFA_ENCRYPTION_KEY`. Le paquet la lit avec `getenv()` : elle doit donc être visible de PHP,
par exemple par un `.env` si le projet le charge (avec `symfony/dotenv`, il faut `usePutenv()` pour que `getenv()`
la voie), par une variable du conteneur, ou par la configuration du serveur. Si PHP-FPM nettoie son environnement
(`clear_env = yes`), la déclarer explicitement dans le pool.

```
TWOFA_ENCRYPTION_KEY=def00000…
```

**Sauvegardes.** Si le projet sauvegarde son `.env` avec la base de données, ne pas y mettre la clé : une fuite de la
sauvegarde livrerait alors secrets et clé. La garder dans un fichier séparé, exclu de la sauvegarde (par exemple un
`env_file` de Docker Compose), et conserver une copie dans le gestionnaire de mots de passe.

Sans clé valide, `c5:package:install` échoue avec un message explicite plutôt que d'installer une 2FA dont les
secrets seraient illisibles. **Changer ou perdre la clé rend les secrets existants illisibles** (les codes de secours
restent utilisables ; `2fa:reset --all` pour repartir de zéro).

### 4. Installer le paquet

```bash
concrete/bin/concrete c5:package:install tacktack_2fa
```

(adapter le chemin à la racine du projet : `vendor/bin/concrete` si le projet l'expose). Si le CLI refuse de
tourner en root, ajouter `--allow-as-root` ou utiliser l'utilisateur du serveur web.

L'installation crée les deux tables (`TwoFactorCredentials`, `TwoFactorRecoveryCodes`), la catégorie de contrôle
d'accès IP, la permission `tacktack_2fa_reset` (accordée aux Administrateurs) et deux pages :

- `/account/two_factor` : activation, statut, régénération des codes de secours, désactivation ;
- `/dashboard/system/registration/two_factor` : politique, utilisateurs concernés, réinitialisation, levée de verrou.

Puis vider le cache pour charger la traduction française :

```bash
concrete/bin/concrete c5:clear-cache
```

### 5. Régler la politique

Au Dashboard (voir « Configuration » ci-dessous) : groupes obligatoires, délai de grâce, nom affiché.
**Par défaut, les Administrateurs sont soumis à la 2FA avec 7 jours de grâce, et le super utilisateur est toujours
concerné.**

### 6. Enrôler le super utilisateur en premier

Se connecter et ouvrir `/account/two_factor` : scanner le QR code avec une application d'authentification, saisir le
code, puis **conserver les 10 codes de secours hors ligne**. Se déconnecter et se reconnecter : l'écran de code doit
s'afficher et accepter le code. Prévenir ensuite les autres comptes concernés avant la fin de leur délai de grâce.

### 7. Prérequis du site

- **Courrier :** les e-mails de sécurité (activation, désactivation, code de secours utilisé, réinitialisation,
  régénération des codes) supposent que l'envoi de courrier fonctionne. Un échec d'envoi est journalisé et ne bloque
  jamais l'action.
- **Apparence :** l'écran de code et l'enrôlement forcé utilisent le thème de base de Concrete, pas celui du site.
- **Langues :** textes en anglais avec traduction française ; une autre langue demande un fichier de traduction
  (`languages/<locale>/LC_MESSAGES/messages.mo`).

Après une mise à jour du paquet ou de ses traductions : `concrete/bin/concrete c5:clear-cache`.

## Configuration

Au Dashboard (Système et réglages > Connexion et enregistrement > Double authentification) :

| Réglage | Défaut | Rôle |
|---|---|---|
| Groupes obligatoires | Administrateurs | Les membres doivent activer la 2FA (hors groupes implicites Invités et Enregistrés). |
| Délai de grâce | 7 jours | Temps laissé avant que l'enrôlement soit obligatoire. 0 = immédiat. |
| Nom affiché | nom du site | Libellé dans l'application d'authentification. |

Les réglages sont enregistrés en base. Les valeurs par défaut sont dans `config/policy.php`.

## Ligne de commande

```bash
concrete/bin/concrete 2fa:status [utilisateur]        # état ; code de sortie 1 si la clé est absente ou invalide
concrete/bin/concrete 2fa:reset <utilisateur> --force # supprime secret et codes de secours, lève les verrous
concrete/bin/concrete 2fa:reset --all --force         # idem pour tous les comptes
concrete/bin/concrete 2fa:generate-key                # affiche une clé neuve
```

`utilisateur` : identifiant, nom d'utilisateur ou adresse e-mail.

### Récupérer un accès perdu

Plus aucun administrateur ne peut se connecter : sur le serveur, `2fa:reset <administrateur> --force`. Si la clé
`TWOFA_ENCRYPTION_KEY` est perdue, les codes de secours permettent encore de se connecter ; sinon `2fa:reset --all`.

## Limites de la v1

- Les appels d'API authentifiés par jeton OAuth, sans session, ne passent pas par le contrôle 2FA.
- Un enrôlement forcé peut être fait par quelqu'un qui connaît déjà le mot de passe ; l'e-mail « 2FA activée » sert de détection.
- La ligne de commande n'est pas soumise à la 2FA.
- « Se connecter en tant que » demande le code de l'utilisateur cible, **sauf pour le super utilisateur** (uID 1) : son passage est exempté de l'étape 2FA, journalisé (canal Authentification) et sans modification possible de la 2FA de la cible pendant la session.

## Développement

```bash
composer install
vendor/bin/pest tests
```

Les tests unitaires couvrent la logique pure (TOTP, codes de secours, états, verrou, liste blanche, redirection).
Le reste se vérifie par appels HTTP sur une installation Concrete de développement.

## Licence

MIT.
