<?php

namespace TackTack\TwoFactor\Service;

use Concrete\Core\Application\Application;
use Concrete\Core\Logging\Channels;
use Concrete\Core\Logging\LoggerFactory;

/**
 * E-mails de sécurité (docs/paquet-2fa.md §3.9). Un échec d'envoi est journalisé et ne
 * bloque jamais l'action.
 */
class Notifier
{
    /** @var Application */
    protected $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function enabled(string $email, string $siteName): void
    {
        $this->send('two_factor_enabled', $email, ['siteName' => $siteName]);
    }

    public function disabled(string $email, string $siteName): void
    {
        $this->send('two_factor_disabled', $email, ['siteName' => $siteName]);
    }

    public function codesRegenerated(string $email, string $siteName): void
    {
        $this->send('two_factor_codes_regenerated', $email, ['siteName' => $siteName]);
    }

    public function resetByOther(string $email, string $siteName): void
    {
        $this->send('two_factor_reset', $email, ['siteName' => $siteName]);
    }

    public function recoveryCodeUsed(string $email, string $siteName, int $remaining): void
    {
        $this->send('two_factor_recovery_used', $email, ['siteName' => $siteName, 'remaining' => $remaining]);
    }

    protected function send(string $template, string $email, array $params): void
    {
        try {
            $mail = $this->app->make('mail');
            $mail->to($email);
            foreach ($params as $key => $value) {
                $mail->addParameter($key, $value);
            }
            $mail->load($template, 'tacktack_2fa');
            $mail->sendMail();
        } catch (\Throwable $e) {
            $this->app->make(LoggerFactory::class)
                ->createLogger(Channels::CHANNEL_AUTHENTICATION)
                ->warning('2FA : échec d\'envoi de l\'e-mail "' . $template . '" : ' . $e->getMessage());
        }
    }
}
