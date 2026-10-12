<?php

namespace TackTack\TwoFactor\Service;

use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;

/**
 * Liste des utilisateurs concernés par la 2FA et leur statut,
 * partagée par le Dashboard et la commande 2fa:status.
 */
class OverviewService
{
    public const ENABLED = 'enabled';

    protected $em;
    protected $resolver;
    protected $config;

    public function __construct(EntityManagerInterface $em, PolicyResolver $resolver, PolicyConfig $config)
    {
        $this->em = $em;
        $this->resolver = $resolver;
        $this->config = $config;
    }

    /**
     * @return array<int, array{uID:int, uName:string, uEmail:string, status:string, enabledAt:?string, graceEndsAt:?string, failedAttempts:int, lockedUntil:?string, locked:bool}>
     */
    public function concernedUsers(?DateTimeImmutable $now = null): array
    {
        $now = $now ?? new DateTimeImmutable();
        $graceDays = $this->config->graceDays();
        $groups = $this->config->groups();

        $sql = 'SELECT DISTINCT u.uID, u.uName, u.uEmail, c.confirmedAt, c.enforcementStartedAt, c.failedAttempts, c.lockedUntil'
            . ' FROM Users u LEFT JOIN TwoFactorCredentials c ON c.uID = u.uID LEFT JOIN UserGroups ug ON ug.uID = u.uID'
            . ' WHERE u.uID = ' . USER_SUPER_ID . ' OR c.confirmedAt IS NOT NULL';
        $params = [];
        if ($groups) {
            $sql .= ' OR ug.gID IN (' . implode(',', array_fill(0, count($groups), '?')) . ')';
            $params = $groups;
        }
        $sql .= ' ORDER BY u.uName';

        $rows = [];
        foreach ($this->em->getConnection()->fetchAllAssociative($sql, $params) as $r) {
            $enrolled = $r['confirmedAt'] !== null;
            $start = $r['enforcementStartedAt'] !== null ? new DateTimeImmutable($r['enforcementStartedAt']) : null;
            $state = $this->resolver->resolve((int) $r['uID'], $enrolled, true, $start, $graceDays, null, $now);
            $locked = $r['lockedUntil'] !== null && new DateTimeImmutable($r['lockedUntil']) > $now;

            $rows[] = [
                'uID' => (int) $r['uID'],
                'uName' => (string) $r['uName'],
                'uEmail' => (string) $r['uEmail'],
                'status' => $enrolled ? self::ENABLED : $state,
                'enabledAt' => $r['confirmedAt'],
                'graceEndsAt' => ($state === PolicyResolver::GRACE && $start !== null) ? $start->modify('+' . max(0, $graceDays) . ' days')->format('Y-m-d') : null,
                'failedAttempts' => (int) $r['failedAttempts'],
                'lockedUntil' => $r['lockedUntil'],
                'locked' => $locked,
            ];
        }

        return $rows;
    }
}
