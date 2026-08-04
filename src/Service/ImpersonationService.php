<?php

namespace XD\Impersonate\Service;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\FieldType\DBDatetime;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Permission;
use XD\Impersonate\Model\ImpersonationLog;

/**
 * Single source of truth for who may impersonate whom, and for actually starting/stopping an
 * impersonation session. XD\Impersonate\Control\ImpersonateController and the auto-expiry middleware
 * both call into this class rather than duplicating the permission or state-change logic — anywhere
 * else that needs to check or act on impersonation state (e.g. a "you are viewing as X" banner in a
 * consuming app's own templates) should also call this class, not read the session directly.
 *
 * All state is stored server-side in the PHP session — nothing here is ever serialised to the client,
 * so there is no session data for a user to tamper with directly.
 */
class ImpersonationService
{
    use Configurable;

    private static string $allowed_group_code = 'Impersonators';

    private static string $allowed_permission_code = 'IMPERSONATE_MEMBERS';

    private static bool $allow_impersonating_privileged = false;

    private static int $max_duration = 1800;

    private const SESSION_ORIGINAL_ID = 'XDImpersonate.OriginalMemberID';
    private const SESSION_STARTED_AT  = 'XDImpersonate.StartedAt';
    private const SESSION_LOG_ID      = 'XDImpersonate.LogID';

    /**
     * Can $actor impersonate anyone at all? (Whether they can impersonate a *specific* target is a
     * separate question — see canBeImpersonated().)
     */
    public static function canImpersonate(Member $actor): bool
    {
        return Permission::checkMember($actor, 'ADMIN')
            || Permission::checkMember($actor, (string) static::config()->get('allowed_permission_code'))
            || static::isInAllowedGroup($actor);
    }

    /**
     * Can $actor impersonate $target specifically? Blocks impersonating yourself, and — unless
     * allow_impersonating_privileged is on and $actor is a genuine ADMIN — blocks impersonating anyone
     * who is themselves an ADMIN or in the allowed group. A non-admin Impersonators-group member can
     * never impersonate a privileged account, regardless of config.
     */
    public static function canBeImpersonated(Member $actor, Member $target): bool
    {
        if ((int) $target->ID === (int) $actor->ID) {
            return false;
        }

        $targetIsPrivileged = Permission::checkMember($target, 'ADMIN')
            || Permission::checkMember($target, (string) static::config()->get('allowed_permission_code'))
            || static::isInAllowedGroup($target);

        if (!$targetIsPrivileged) {
            return true;
        }

        $actorIsAdmin = Permission::checkMember($actor, 'ADMIN');

        return $actorIsAdmin && (bool) static::config()->get('allow_impersonating_privileged');
    }

    /**
     * Begin impersonating $target as $actor. Assumes canImpersonate()/canBeImpersonated() have already
     * been checked by the caller — this method does not re-check permissions itself.
     */
    public static function start(Member $actor, Member $target, HTTPRequest $request): void
    {
        $log = ImpersonationLog::create();
        $log->ActorMemberID = $actor->ID;
        $log->TargetMemberID = $target->ID;
        $log->StartedAt = DBDatetime::now()->getValue();
        $log->write();

        $session = $request->getSession();
        $session->set(static::SESSION_ORIGINAL_ID, $actor->ID);
        $session->set(static::SESSION_STARTED_AT, time());
        $session->set(static::SESSION_LOG_ID, $log->ID);

        static::getIdentityStore()->logIn($target, false, $request);
    }

    /**
     * End the current impersonation session (if any) and log back in as the original Member.
     *
     * @param 'manual'|'expired' $reason
     */
    public static function stop(HTTPRequest $request, string $reason): void
    {
        $session = $request->getSession();
        $originalID = $session->get(static::SESSION_ORIGINAL_ID);
        $logID = $session->get(static::SESSION_LOG_ID);

        $original = $originalID ? Member::get()->byID($originalID) : null;

        if ($original) {
            static::getIdentityStore()->logIn($original, false, $request);
        } else {
            static::getIdentityStore()->logOut($request);
        }

        if ($logID) {
            $log = ImpersonationLog::get()->byID($logID);
            if ($log && $log->exists()) {
                $log->StoppedAt = DBDatetime::now()->getValue();
                $log->StoppedReason = $reason;
                $log->write();
            }
        }

        $session->clear(static::SESSION_ORIGINAL_ID);
        $session->clear(static::SESSION_STARTED_AT);
        $session->clear(static::SESSION_LOG_ID);
    }

    public static function isImpersonating(?HTTPRequest $request = null): bool
    {
        return (bool) static::session($request)->get(static::SESSION_ORIGINAL_ID);
    }

    public static function getOriginalMember(?HTTPRequest $request = null): ?Member
    {
        $id = static::session($request)->get(static::SESSION_ORIGINAL_ID);
        return $id ? Member::get()->byID($id) : null;
    }

    public static function isExpired(?HTTPRequest $request = null): bool
    {
        $startedAt = static::session($request)->get(static::SESSION_STARTED_AT);

        if (!$startedAt) {
            return false;
        }

        return (time() - (int) $startedAt) > (int) static::config()->get('max_duration');
    }

    private static function isInAllowedGroup(Member $member): bool
    {
        $groupCode = static::config()->get('allowed_group_code');
        return (bool) $member->Groups()->filter('Code', $groupCode)->count();
    }

    private static function getIdentityStore(): IdentityStore
    {
        return Injector::inst()->get(IdentityStore::class);
    }

    private static function session(?HTTPRequest $request)
    {
        return ($request ?? Controller::curr()->getRequest())->getSession();
    }
}
