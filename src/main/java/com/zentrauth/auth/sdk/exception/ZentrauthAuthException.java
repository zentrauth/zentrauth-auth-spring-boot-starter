package com.zentrauth.auth.sdk.exception;

public class ZentrauthAuthException extends RuntimeException {
    private final int statusCode;

    public ZentrauthAuthException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public ZentrauthAuthException(String message, int statusCode, Throwable cause) {
        super(message, cause);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
