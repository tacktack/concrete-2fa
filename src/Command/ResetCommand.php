<?php

namespace TackTack\TwoFactor\Command;

use Concrete\Core\Console\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;
use TackTack\TwoFactor\Service\EnrollmentException;
use TackTack\TwoFactor\Service\ResetService;

/**
 * 2fa:reset <utilisateur>|--all [--force] — supprime secret et codes de secours, lève les
 * verrous. Dernier recours quand plus aucun administrateur ne peut se connecter.
 */
class ResetCommand extends Command
{
    use UserResolver;

    protected function configure()
    {
        $this
            ->setName('2fa:reset')
            ->setDescription('Reset two-factor authentication for a user (or all users) and lift lockouts.')
            ->addArgument('user', InputArgument::OPTIONAL, 'User ID, username or e-mail address')
            ->addOption('all', null, InputOption::VALUE_NONE, 'Reset every user')
            ->addOption('force', 'f', InputOption::VALUE_NONE, 'Do not ask for confirmation')
        ;
    }

    public function handle(ResetService $reset)
    {
        $all = (bool) $this->input->getOption('all');
        $identifier = $this->input->getArgument('user');
        if ($all === ($identifier !== null)) {
            $this->output->writeln('<error>Give either a user or --all.</error>');

            return static::INVALID;
        }

        if ($all) {
            $ids = $reset->allUserIDs();
            $what = count($ids) . ' user(s)';
        } else {
            $uID = $this->resolveUserID($identifier);
            if ($uID === null) {
                $this->output->writeln('<error>User not found.</error>');

                return static::FAILURE;
            }
            $ids = [$uID];
            $what = 'user ' . $uID;
        }

        if (!$this->input->getOption('force') && !$this->output->confirm('Reset two-factor authentication for ' . $what . '?', false)) {
            $this->output->writeln('Aborted.');

            return static::FAILURE;
        }

        $done = 0;
        foreach ($ids as $uID) {
            try {
                $reset->reset($uID, 'command line');
                ++$done;
            } catch (EnrollmentException $e) {
                $this->output->writeln('<comment>User ' . $uID . ': ' . $e->getMessage() . '</comment>');
            }
        }
        $this->output->writeln($done . ' user(s) reset.');

        return static::SUCCESS;
    }

}
