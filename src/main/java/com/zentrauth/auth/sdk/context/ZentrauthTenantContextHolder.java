package com.zentrauth.auth.sdk.context;

public final class ZentrauthTenantContextHolder {
    private static final ThreadLocal<ZentrauthTenantContext> CONTEXT = new ThreadLocal<>();

    private ZentrauthTenantContextHolder() {
    }

    public static void setContext(ZentrauthTenantContext context) {
        CONTEXT.set(context);
    }

    public static ZentrauthTenantContext getContext() {
        return CONTEXT.get();
    }

    public static String getZentrauthTenantId() {
        ZentrauthTenantContext context = CONTEXT.get();
        return context != null ? context.getZentrauthTenantId() : null;
    }

    public static void clear() {
        CONTEXT.remove();
    }
}
