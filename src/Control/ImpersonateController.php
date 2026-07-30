<?php

namespace XD\Impersonate\Control;

use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\Security\SecurityToken;
use SilverStripe\Security\SudoMode\SudoModeServiceInterface;
use XD\Impersonate\Service\ImpersonationService;

/**
 * POST /impersonate/start/{MemberID} — begin impersonating the given Member.
 * POST /impersonate/stop            — end the current impersonation session.
 *
 * Every state change is delegated to XD\Impersonate\Service\ImpersonationService — this controller's
 * only job is to gate the HTTP request itself: verb, CSRF, and permission checks, all re-evaluated
 * fresh on every request against the *actual* currently logged-in Member. Nothing here trusts
 * anything supplied by the client beyond the target Member ID, which is itself re-validated against
 * ImpersonationService::canBeImpersonated() before anything happens.
 */
class ImpersonateController extends Controller
{
    private static array $allowed_actions = [
        'start',
        'stop',
    ];

    private static bool $require_sudo_mode = true;

    public function start(HTTPRequest $request): HTTPResponse
    {
        if (!$request->isPOST()) {
            return $this->errorResponse(
                _t(__CLASS__ . '.POST_REQUIRED', 'This action requires a POST request.'),
                405
            );
        }

        if (!SecurityToken::inst()->checkRequest($request)) {
            return $this->errorResponse(
                _t(__CLASS__ . '.CSRF_FAILURE', 'Your session timed out. Please refresh and try again.'),
                403
            );
        }

        $actor = Security::getCurrentUser();

        if (!$actor) {
            return $this->errorResponse(
                _t(__CLASS__ . '.NOT_LOGGED_IN', 'You must be logged in to do this.'),
                403
            );
        }

        if (ImpersonationService::isImpersonating($request)) {
            return $this->errorResponse(
                _t(__CLASS__ . '.ALREADY_IMPERSONATING', 'You are already impersonating someone. Stop that session first.'),
                400
            );
        }

        if (!ImpersonationService::canImpersonate($actor)) {
            return $this->errorResponse(
                _t(__CLASS__ . '.NOT_ALLOWED', 'You do not have permission to impersonate other members.'),
                403
            );
        }

        if ($this->config()->get('require_sudo_mode') && !$this->getSudoModeService()->check($request->getSession())) {
            return $this->errorResponse(
                _t(__CLASS__ . '.SUDO_MODE_REQUIRED', 'Please re-authenticate before starting an impersonation session.'),
                403
            );
        }

        $targetID = (int) $request->param('ID');
        $target = $targetID ? Member::get()->byID($targetID) : null;

        if (!$target || !$target->exists()) {
            return $this->errorResponse(
                _t(__CLASS__ . '.MEMBER_NOT_FOUND', 'That member could not be found.'),
                404
            );
        }

        if (!ImpersonationService::canBeImpersonated($actor, $target)) {
            return $this->errorResponse(
                _t(__CLASS__ . '.TARGET_NOT_ALLOWED', 'This member cannot be impersonated.'),
                403
            );
        }

        ImpersonationService::start($actor, $target, $request);

        return $this->jsonResponse(['success' => true]);
    }

    public function stop(HTTPRequest $request): HTTPResponse
    {
        if (!$request->isPOST()) {
            return $this->errorResponse(
                _t(__CLASS__ . '.POST_REQUIRED', 'This action requires a POST request.'),
                405
            );
        }

        if (!SecurityToken::inst()->checkRequest($request)) {
            return $this->errorResponse(
                _t(__CLASS__ . '.CSRF_FAILURE', 'Your session timed out. Please refresh and try again.'),
                403
            );
        }

        if (!ImpersonationService::isImpersonating($request)) {
            return $this->errorResponse(
                _t(__CLASS__ . '.NOT_IMPERSONATING', 'You are not currently impersonating anyone.'),
                400
            );
        }

        ImpersonationService::stop($request, 'manual');

        return $this->jsonResponse(['success' => true]);
    }

    private function getSudoModeService(): SudoModeServiceInterface
    {
        return Injector::inst()->get(SudoModeServiceInterface::class);
    }

    private function jsonResponse(array $data, int $statusCode = 200): HTTPResponse
    {
        return HTTPResponse::create((string) json_encode($data), $statusCode)
            ->addHeader('Content-Type', 'application/json');
    }

    private function errorResponse(string $message, int $statusCode): HTTPResponse
    {
        return $this->jsonResponse(['error' => $message], $statusCode);
    }
}
