package com.zentrauth.auth.sdk.context;

import java.util.Objects;

public final class ZentrauthTenantContext {
    private final String zentrauthTenantId;

    public ZentrauthTenantContext(String zentrauthTenantId) {
        this.zentrauthTenantId = Objects.requireNonNull(zentrauthTenantId, "zentrauthTenantId");
    }

    public String getZentrauthTenantId() {
        return zentrauthTenantId;
    }
}
