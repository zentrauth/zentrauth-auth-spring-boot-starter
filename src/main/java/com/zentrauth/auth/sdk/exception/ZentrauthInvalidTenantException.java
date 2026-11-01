package com.zentrauth.auth.sdk.exception;

public class ZentrauthInvalidTenantException extends ZentrauthAuthException {
    public ZentrauthInvalidTenantException(String message) {
        super(message, 403);
    }
}
