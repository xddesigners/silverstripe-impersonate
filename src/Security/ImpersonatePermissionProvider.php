<?php

namespace XD\Impersonate\Security;

use SilverStripe\Security\PermissionProvider;
use XD\Impersonate\Service\ImpersonationService;

/**
 * Registers the "impersonate" permission so it can be granted to any Group in the CMS
 * (Security > Groups > Permissions). Holders — plus ADMINs, and members of the allowed group — may
 * impersonate other members (see {@link ImpersonationService::canImpersonate()}).
 *
 * The permission code is configurable via ImpersonationService.allowed_permission_code
 * (default IMPERSONATE_MEMBERS). PermissionProvider implementations are auto-discovered by the
 * framework, so no config registration is needed.
 */
class ImpersonatePermissionProvider implements PermissionProvider
{
    public function providePermissions(): array
    {
        $code = (string) ImpersonationService::config()->get('allowed_permission_code');
        if ($code === '') {
            return [];
        }

        return [
            $code => [
                'name'     => _t(__CLASS__ . '.PERMISSION_NAME', 'Impersonate other members'),
                'category' => _t(__CLASS__ . '.CATEGORY', 'Impersonation'),
                'help'     => _t(
                    __CLASS__ . '.PERMISSION_HELP',
                    'Log in as (impersonate) other members. A powerful permission — grant sparingly. '
                    . 'Privileged accounts (admins / impersonators) still cannot be impersonated unless '
                    . 'explicitly allowed in config.'
                ),
                'sort'     => 100,
            ],
        ];
    }
}
