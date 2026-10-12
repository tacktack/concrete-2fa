<?php

namespace TackTack\TwoFactor\Command;

use Concrete\Core\Console\Command;
use Symfony\Component\Console\Input\InputArgument;
use TackTack\TwoFactor\Service\OverviewService;
use TackTack\TwoFactor\Service\SecretCipher;

/**
 * 2fa:status [utilisateur] — état de la 2FA (§3.10). Sort avec un code non nul si la clé de
 * chiffrement est absente ou invalide : le workflow de déploiement s'en sert (§4).
 */
class StatusCommand extends Command
{
    use UserResolver;

    protected function configure()
    {
        $this
            ->setName('2fa:status')
            ->setDescription('Show the two-factor authentication status (exits non-zero if the encryption key is missing or invalid).')
            ->addArgument('user', InputArgument::OPTIONAL, 'User ID, username or e-mail address')
        ;
    }

    public function handle(SecretCipher $cipher, OverviewService $overview)
    {
        if (!$cipher->isKeyConfigured()) {
            $this->output->writeln('<error>' . SecretCipher::ENV_VAR . ' is missing or invalid.</error>');

            return static::FAILURE;
        }
        $this->output->writeln(SecretCipher::ENV_VAR . ': OK');

        $users = $overview->concernedUsers();
        $filter = $this->input->getArgument('user');
        if ($filter !== null) {
            $uID = $this->resolveUserID($filter);
            if ($uID === null) {
                $this->output->writeln('<error>User not found.</error>');

                return static::FAILURE;
            }
            $users = array_values(array_filter($users, static function ($u) use ($uID) {
                return $u['uID'] === $uID;
            }));
            if (!$users) {
                $this->output->writeln('User ' . $uID . ': not concerned by two-factor authentication.');

                return static::SUCCESS;
            }
        }

        foreach ($users as $u) {
            $this->output->writeln(sprintf(
                '%d %s <%s>: %s%s%s',
                $u['uID'],
                $u['uName'],
                $u['uEmail'],
                $u['status'],
                $u['graceEndsAt'] ? ' (grace until ' . $u['graceEndsAt'] . ')' : '',
                $u['locked'] ? ' [LOCKED until ' . $u['lockedUntil'] . ']' : ''
            ));
        }
        if ($filter === null && !$users) {
            $this->output->writeln('No concerned user.');
        }

        return static::SUCCESS;
    }
}
