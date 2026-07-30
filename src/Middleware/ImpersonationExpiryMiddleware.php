<?php

namespace XD\Impersonate\Middleware;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use XD\Impersonate\Service\ImpersonationService;

/**
 * Runs on every request. If an impersonation session has been active longer than the configured
 * max_duration, it is force-reverted before the request is handled — so an impersonated session left
 * open (e.g. a forgotten browser tab) can't linger indefinitely.
 */
class ImpersonationExpiryMiddleware implements HTTPMiddleware
{
    public function process(HTTPRequest $request, callable $delegate)
    {
        if (ImpersonationService::isImpersonating($request) && ImpersonationService::isExpired($request)) {
            ImpersonationService::stop($request, 'expired');
        }

        return $delegate($request);
    }
}
