package com.zentrauth.auth.sdk.filter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.zentrauth.auth.sdk.autoconfigure.ZentrauthAuthProperties;
import com.zentrauth.auth.sdk.context.ZentrauthTenantContextHolder;
import com.zentrauth.auth.sdk.security.ZentrauthJwkProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

class ZentrauthTenantSecurityFilterTest {
    private static final String ISSUER = "https://auth.zentrauth.com";
    private static final String ZENTRAUTH_TENANT_ID = "zentrauth-tenant-123";

    private com.nimbusds.jose.jwk.RSAKey signingKey;
    private ZentrauthTenantSecurityFilter filter;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        ZentrauthJwkProvider provider = keyId -> signingKey.toPublicJWK();
        ZentrauthAuthProperties properties = new ZentrauthAuthProperties();
        filter = new ZentrauthTenantSecurityFilter(properties, provider);
    }

    @AfterEach
    void clearThreadLocals() {
        ZentrauthTenantContextHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticatesAndBindsTenantForTheRequest() throws Exception {
        MockHttpServletRequest request = requestWithToken(createToken(new Date(System.currentTimeMillis() + 60_000)));
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
            assertEquals(ZENTRAUTH_TENANT_ID, ZentrauthTenantContextHolder.getZentrauthTenantId());
            assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
        });

        assertEquals(200, response.getStatus());
        assertNull(ZentrauthTenantContextHolder.getContext());
    }

    @Test
    void rejectsExpiredTokenAndClearsTenantContext() throws Exception {
        MockHttpServletRequest request = requestWithToken(createToken(new Date(System.currentTimeMillis() - 1_000)));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
        });

        assertEquals(401, response.getStatus());
        assertNull(ZentrauthTenantContextHolder.getContext());
    }

    @Test
    void rejectsMismatchedTenantHeaderAndClearsTenantContext() throws Exception {
        MockHttpServletRequest request = requestWithToken(createToken(new Date(System.currentTimeMillis() + 60_000)));
        request.addHeader("ZentrAuth-Tenant-ID", "other-tenant");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
        });

        assertEquals(403, response.getStatus());
        assertNull(ZentrauthTenantContextHolder.getContext());
    }

    @Test
    void rejectsMissingTenantClaimAndClearsTenantContext() throws Exception {
        MockHttpServletRequest request = requestWithToken(
                createToken(new Date(System.currentTimeMillis() + 60_000), null)
        );
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (servletRequest, servletResponse) -> {
        });

        assertEquals(403, response.getStatus());
        assertNull(ZentrauthTenantContextHolder.getContext());
    }

    private MockHttpServletRequest requestWithToken(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/api/resource");
        request.addHeader("Authorization", "Bearer " + token);
        return request;
    }

    private String createToken(Date expiration) throws Exception {
        return createToken(expiration, ZENTRAUTH_TENANT_ID);
    }

    private String createToken(Date expiration, String tenantId) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("user-456")
                .expirationTime(expiration)
                .claim("zentrauth_tenant_id", tenantId)
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
                claims
        );
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }
}
