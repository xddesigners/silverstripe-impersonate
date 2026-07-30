<?php

namespace XD\Impersonate\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

/**
 * An audit record of a single impersonation session. Deliberately immutable from any CMS/API surface —
 * canCreate/canEdit/canDelete always return false — so the trail can't be edited or removed after the
 * fact by anyone, including Administrators. The module's own service code still writes to it directly
 * via write(), which is unaffected by these checks (they only gate CMS/GraphQL/API access).
 *
 * @property string $StartedAt
 * @property string $StoppedAt
 * @property string $StoppedReason
 * @property int $ActorMemberID
 * @property int $TargetMemberID
 * @method Member ActorMember()
 * @method Member TargetMember()
 */
class ImpersonationLog extends DataObject
{
    private static $table_name = 'XD_ImpersonationLog';

    private static $db = [
        'StartedAt'     => 'Datetime',
        'StoppedAt'     => 'Datetime',
        'StoppedReason' => 'Enum("manual,expired","manual")',
    ];

    private static $has_one = [
        'ActorMember'  => Member::class,
        'TargetMember' => Member::class,
    ];

    private static $summary_fields = [
        'ActorMember.Title'  => 'Impersonator',
        'TargetMember.Title' => 'Impersonating',
        'StartedAt'          => 'Started',
        'StoppedAt'          => 'Stopped',
        'StoppedReason'      => 'Reason',
    ];

    private static $default_sort = 'StartedAt DESC';

    public function canCreate($member = null, $context = [])
    {
        return false;
    }

    public function canEdit($member = null)
    {
        return false;
    }

    public function canDelete($member = null)
    {
        return false;
    }
}
