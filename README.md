# concrete-2fa

Double authentification TOTP (Google Authenticator, Authy, 1Password…) pour Concrete CMS 9.

- Codes à usage unique conformes RFC 6238 (SHA-1, 6 chiffres, pas de 30 s, tolérance ±1 pas), rejeu refusé.
- Secret chiffré au repos (defuse/php-encryption) ; la clé vit dans une variable d'environnement, jamais en base.
- QR code généré côté serveur, en SVG : le secret ne part vers aucun service tiers.
- 10 codes de secours à usage unique, hachés, régénérables.
- Politique par groupe, avec délai de grâce ; le super utilisateur est toujours concerné.
- Verrou après 5 échecs (15 min) et bannissement IP (20 échecs en 10 min).
- Contrôle par middleware HTTP, **en échec fermé** : il couvre tous les chemins de connexion (mot de passe,
  OAuth, « rester connecté », « Se connecter en tant que »).
- Pas de « mot de passe d'urgence » : codes de secours, réinitialisation par un administrateur ou ligne de commande.

Le document d'architecture qui fige les décisions de conception et la liste des tests de contournement vit dans
le dépôt du premier site intégrateur : `docs/paquet-2fa.md` (dépôt Oli).

## Installation

```bash
composer require tacktack/concrete-2fa
```

Le paquet s'installe dans `packages/tacktack_2fa` (handle `tacktack_2fa`).

### 1. Générer la clé de chiffrement — avant l'installation

Une clé **par environnement**, jamais versionnée. Les commandes `2fa:*` n'existent qu'une fois le paquet installé :
avant, utiliser l'outil fourni par defuse :

```bash
vendor/bin/generate-defuse-key
```

Placer le résultat dans l'environnement du site (fichier `.env` ou variables du conteneur) :

```
TWOFA_ENCRYPTION_KEY="def00000…"
```

Sans clé valide, `c5:package:install` échoue avec un message explicite plutôt que d'installer une 2FA dont les
secrets seraient illisibles. **Changer la clé rend les secrets existants illisibles** (les codes de secours restent
utilisables ; `2fa:reset --all` pour repartir de zéro).

### 2. Installer

```bash
concrete/bin/concrete c5:package:install tacktack_2fa
```

L'installation crée les deux tables, la catégorie de contrôle d'accès IP, la permission
`tacktack_2fa_reset` (accordée aux Administrateurs) et deux pages :

- `/account/two_factor` : activation, statut, régénération des codes de secours, désactivation ;
- `/dashboard/system/registration/two_factor` : politique, utilisateurs concernés, réinitialisation, levée de verrou.

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
- « Se connecter en tant que » demande le code de l'utilisateur cible.

## Développement

```bash
composer install
vendor/bin/pest tests
```

Les tests unitaires couvrent la logique pure (TOTP, codes de secours, états, verrou, liste blanche, redirection).
Le reste se vérifie par appels HTTP sur une installation Concrete de développement.

## Licence

MIT.
