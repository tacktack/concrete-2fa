<?php

namespace TackTack\TwoFactor\Command;

use Concrete\Core\Console\Command;
use TackTack\TwoFactor\Service\SecretCipher;

/**
 * 2fa:generate-key — affiche une clé neuve à placer dans TWOFA_ENCRYPTION_KEY (§3.10).
 */
class GenerateKeyCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('2fa:generate-key')
            ->setDescription('Print a new encryption key to put in the TWOFA_ENCRYPTION_KEY environment variable.')
            ->setHelp('Use one key per environment and never commit it. Changing the key makes existing secrets unreadable (use 2fa:reset --all afterwards).')
        ;
    }

    public function handle(SecretCipher $cipher)
    {
        $this->output->writeln($cipher->generateKey());

        return static::SUCCESS;
    }
}
