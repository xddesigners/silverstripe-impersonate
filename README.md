# silverstripe-impersonate

Lets Administrators — or members granted an impersonate permission, or in a designated Group — temporarily
log in as another Member, with a safe, auditable way back to their own account.

Login (both becoming the target, and switching back) is always completed through SilverStripe's own
`IdentityStore` — this module never maintains a parallel session mechanism. While impersonating,
`Security::getCurrentUser()` genuinely returns the target Member, exactly as if they had logged in
themselves.

## Installation

```bash
composer require xddesigners/silverstripe-impersonate
```

### Who can impersonate

Three ways, checked on every request against the *actual* logged-in Member:

1. **ADMIN** permission — always sufficient, regardless of anything below.
2. The **Impersonate other members** permission (`IMPERSONATE_MEMBERS`) — grantable to any Group under
   _Security → Groups → Permissions_ (category "Impersonation").
3. Membership of the **Impersonators** group (matched by `Code`, default `Impersonators`).

Both #2 and #3 are set up for you: on `dev/build` the module **auto-seeds the Impersonators group holding
that permission**, so it exists in the CMS ready to drop members into — no manual group/permission setup
needed. (The group's `Code` is stored exactly as configured, since the module matches on it.) Both the
permission code and the group code are configurable — see [Configuration](#configuration).

## Usage

```
POST /impersonate/start/{MemberID}   (with SecurityID in the request body)
POST /impersonate/stop               (with SecurityID in the request body)
```

Both require a valid SilverStripe CSRF token (`SecurityToken`) and a POST request — GET is rejected
outright, so neither action can be triggered by a crafted link or image tag.

In your own templates/frontend, check the current state via:

```php
use XD\Impersonate\Service\ImpersonationService;

if (ImpersonationService::isImpersonating()) {
    $originalAdmin = ImpersonationService::getOriginalMember();
    // e.g. render a "Viewing as {name} — [Switch back]" banner
}
```

This module doesn't render any banner itself — it only exposes the state, so it doesn't assume or
interfere with whatever frontend stack a consuming site uses.

## Safety model

Every one of these is a deliberate, tested design decision, not an afterthought:

1. **CSRF + POST-only on both actions.** Neither `start` nor `stop` can be triggered by anything other
   than an intentional, same-origin form submission carrying a fresh `SecurityID`.
2. **Permission is re-checked on every single request, from the *actual* logged-in Member** —
   `ImpersonationService::canImpersonate()` never trusts anything the client claims. There's no cached
   "is admin" flag anywhere.
3. **No nested impersonation.** You cannot start impersonating a second person while already
   impersonating someone else — `start` hard-rejects if a session is already active. You always know
   exactly one original identity is being tracked at a time.
4. **No privilege escalation via the target.** You can never impersonate a Member who is themselves
   privileged — an ADMIN, a holder of the impersonate permission, or a member of the Impersonators group —
   unless *you* are a genuine ADMIN **and** the site has explicitly opted in via
   `allow_impersonating_privileged: true`. A non-admin impersonator can never impersonate a privileged
   account, regardless of that config flag — this is the main defence against using the feature itself to
   escalate privileges.
5. **Optional sudo-mode gate** (`require_sudo_mode`, default on) — requires a recent re-authentication
   (SilverStripe's own elevated-session check) before an impersonation session can begin, the same
   mechanism the framework already uses to gate other sensitive actions.
6. **Auto-expiry.** A background middleware checks every request; if an impersonation session has run
   longer than `max_duration` (default 30 minutes), it is force-reverted before that request is even
   handled. A forgotten browser tab can't leave a live impersonation session open indefinitely.
7. **All state lives server-side, in the PHP session only** — nothing this module tracks is ever
   serialised to the client (no cookie payload, no JS-readable value, no URL parameter). There is no
   session state here for a user to read or tamper with directly.
8. **Session ID is regenerated on every login/logout transition**, because both are completed via
   `IdentityStore::logIn()`/`logOut()` — the framework's own login mechanics, which already defend
   against session fixation. This module never bypasses that.
9. **No persistent/"remember me" login**, ever, for either the impersonated session or the reversion
   back to the original account — both are session-lifetime only.
10. **Immutable audit log.** Every session (start, stop, and *why* it stopped — manual vs. expired) is
    recorded in `ImpersonationLog`. `canCreate()`/`canEdit()`/`canDelete()` always return `false`, so the
    trail cannot be altered or removed via any CMS or API surface, including by an Administrator — only
    this module's own internal code writes to it.

## Configuration

```yaml
XD\Impersonate\Service\ImpersonationService:
  allowed_group_code: 'Impersonators'         # Group (by Code) whose members may impersonate
  allowed_permission_code: 'IMPERSONATE_MEMBERS' # permission that grants impersonation; '' to disable
  allow_impersonating_privileged: false
  max_duration: 1800 # seconds

XD\Impersonate\Control\ImpersonateController:
  require_sudo_mode: true
```

The permission is registered by `ImpersonatePermissionProvider` (auto-discovered) and the Impersonators
group is seeded by `ImpersonatorsGroupExtension` on `Group` — both keyed off the codes above, so overriding
a code renames the permission/group the module looks for and seeds.
