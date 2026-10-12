<?php

namespace TackTack\TwoFactor\Command;

use Concrete\Core\User\UserInfo;

/**
 * Identifie un utilisateur à partir d'un uID, d'un nom d'utilisateur ou d'une adresse e-mail.
 */
trait UserResolver
{
    protected function resolveUserID(string $identifier): ?int
    {
        $identifier = trim($identifier);
        if ($identifier === '') {
            return null;
        }
        if (ctype_digit($identifier)) {
            $ui = UserInfo::getByID((int) $identifier);
        } else {
            $ui = strpos($identifier, '@') !== false ? UserInfo::getByEmail($identifier) : UserInfo::getByUserName($identifier);
        }

        return $ui ? (int) $ui->getUserID() : null;
    }
}
