package com.zentrauth.auth.sdk.autoconfigure;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;

import org.junit.jupiter.api.Test;

class ZentrauthAuthPropertiesTest {
    @Test
    void exposesReadableDurationDefaultsAndOverrides() {
        ZentrauthAuthProperties properties = new ZentrauthAuthProperties();

        assertEquals("ZentrAuth-Tenant-ID", properties.getTenantHeader());
        assertEquals(Duration.ofMinutes(15), properties.getJwksCacheDuration());
        assertEquals(Duration.ofSeconds(3), properties.getJwksConnectTimeout());
        assertEquals(Duration.ofSeconds(3), properties.getJwksReadTimeout());

        properties.setJwksCacheDuration(Duration.ofMinutes(5));
        properties.setJwksConnectTimeout(Duration.ofMillis(750));
        properties.setJwksReadTimeout(Duration.ofSeconds(2));

        assertEquals(Duration.ofMinutes(5), properties.getJwksCacheDuration());
        assertEquals(Duration.ofMillis(750), properties.getJwksConnectTimeout());
        assertEquals(Duration.ofSeconds(2), properties.getJwksReadTimeout());
    }
}
