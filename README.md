# concrete-2fa

Double authentification TOTP (Google Authenticator, Authy, 1Password, ...) pour
Concrete CMS 9.

Le document d'architecture qui fige toutes les décisions de conception, l'arborescence
du paquet, les étapes d'exécution et les tests de contournement à dérouler avant mise
en production vit dans le dépôt du premier site intégrateur, pas ici :
`docs/paquet-2fa.md` (dépôt [Oli](https://github.com/tacktack/Oli)).

**En cours de développement — pas encore utilisable en production.** Voir §5 de ce
document pour l'avancement par étape.

## Installation

```bash
composer require tacktack/concrete-2fa:dev-main
concrete/bin/concrete c5:package:install tacktack_2fa
```

Nécessite la variable d'environnement `TWOFA_ENCRYPTION_KEY` (générée avec
`concrete/bin/concrete 2fa:generate-key`, une fois la commande disponible à l'étape 1)
**avant** l'installation : sans elle, `c5:package:install` échoue avec un message
explicite plutôt que d'installer une 2FA dont les secrets ne pourraient pas être
déchiffrés.

## Licence

MIT.
