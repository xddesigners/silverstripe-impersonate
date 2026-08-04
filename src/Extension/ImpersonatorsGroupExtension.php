<?php

namespace XD\Impersonate\Extension;

use SilverStripe\Core\Extension;
use SilverStripe\ORM\DB;
use SilverStripe\Security\Group;
use SilverStripe\Security\Permission;
use XD\Impersonate\Service\ImpersonationService;

/**
 * Seeds the "Impersonators" group so it always exists in the CMS (Security > Groups) for admins to drop
 * members into — membership grants impersonation (see {@link ImpersonationService::canImpersonate()}).
 *
 * Two things make membership work, and this seeder sets up both:
 *  - the group's Code equals ImpersonationService.allowed_group_code (the code the service matches on);
 *  - the group holds the allowed_permission_code permission.
 *
 * The Code is written with setField() to preserve the exact configured value: Group::setCode() runs it
 * through Convert::raw2url(), which would slugify 'Impersonators' to 'impersonators' and — under a
 * case-sensitive collation — never match. Group::onBeforeWrite() only auto-generates Code when it is
 * empty, so a pre-set value survives.
 *
 * Fires from DataObject::requireDefaultRecords() via the onRequireDefaultRecords extension hook (NOT a
 * `requireDefaultRecords` method — that name is not extended). Idempotent across dev/builds.
 */
class ImpersonatorsGroupExtension extends Extension
{
    public function onRequireDefaultRecords(): void
    {
        $groupCode = (string) ImpersonationService::config()->get('allowed_group_code');
        $permCode  = (string) ImpersonationService::config()->get('allowed_permission_code');

        if ($groupCode === '') {
            return;
        }

        $group = Group::get()->filter('Code', $groupCode)->first();
        if (!$group || !$group->exists()) {
            $group = Group::create();
            $group->Title = 'Impersonators';
            $group->Description = 'Members of this group may impersonate other members (in addition to admins).';
            $group->setField('Code', $groupCode); // exact match; bypass Group::setCode() slugifying
            $group->write();
            DB::alteration_message("Impersonators group created (Code: {$groupCode})", 'created');
        }

        if ($permCode !== '' && !Permission::get()->filter(['GroupID' => $group->ID, 'Code' => $permCode])->exists()) {
            Permission::grant($group->ID, $permCode);
            DB::alteration_message("Granted {$permCode} to the Impersonators group", 'created');
        }
    }
}
