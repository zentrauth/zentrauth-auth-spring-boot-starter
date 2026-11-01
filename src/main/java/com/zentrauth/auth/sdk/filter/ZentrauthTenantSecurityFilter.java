package com.zentrauth.auth.sdk.filter;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.zentrauth.auth.sdk.autoconfigure.ZentrauthAuthProperties;
import com.zentrauth.auth.sdk.context.ZentrauthTenantContext;
import com.zentrauth.auth.sdk.context.ZentrauthTenantContextHolder;
import com.zentrauth.auth.sdk.exception.ZentrauthAuthException;
import com.zentrauth.auth.sdk.exception.ZentrauthInvalidTenantException;
import com.zentrauth.auth.sdk.security.ZentrauthJwkProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

public class ZentrauthTenantSecurityFilter extends OncePerRequestFilter {
    private static final String TENANT_CLAIM = "zentrauth_tenant_id";
    private static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = Set.of(
            JWSAlgorithm.RS256,
            JWSAlgorithm.ES256
    );

    private final ZentrauthAuthProperties properties;
    private final ZentrauthJwkProvider jwkProvider;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public ZentrauthTenantSecurityFilter(ZentrauthAuthProperties properties, ZentrauthJwkProvider jwkProvider) {
        this.properties = properties;
        this.jwkProvider = jwkProvider;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return properties.getExcludedPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            try {
                authenticate(request);
            } catch (ZentrauthAuthException exception) {
                response.sendError(exception.getStatusCode());
                return;
            }
            filterChain.doFilter(request, response);
        } finally {
            ZentrauthTenantContextHolder.clear();
        }
    }

    private void authenticate(HttpServletRequest request) {
        String token = extractBearerToken(request.getHeader("Authorization"));
        SignedJWT jwt = parseToken(token);
        JWK key = jwkProvider.get(jwt.getHeader().getKeyID());
        verifySignature(jwt, key);

        JWTClaimsSet claims = readClaims(jwt);
        validateClaims(claims);
        String tenantId = readTenantId(claims);
        String requestedTenant = request.getHeader(properties.getTenantHeader());
        if (requestedTenant != null && !requestedTenant.equals(tenantId)) {
            throw new ZentrauthInvalidTenantException("Tenant header does not match the authenticated tenant");
        }

        ZentrauthTenantContextHolder.setContext(new ZentrauthTenantContext(tenantId));
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(Map.copyOf(claims.getClaims()), null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private String extractBearerToken(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new ZentrauthAuthException("A bearer token is required", 401);
        }
        String token = authorization.substring(7).trim();
        if (token.isEmpty()) {
            throw new ZentrauthAuthException("A bearer token is required", 401);
        }
        return token;
    }

    private SignedJWT parseToken(String token) {
        try {
            return SignedJWT.parse(token);
        } catch (ParseException exception) {
            throw new ZentrauthAuthException("JWT is malformed", 401, exception);
        }
    }

    private void verifySignature(SignedJWT jwt, JWK key) {
        JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
        if (!SUPPORTED_ALGORITHMS.contains(algorithm)) {
            throw new ZentrauthAuthException("JWT signing algorithm is not supported", 401);
        }

        try {
            JWSVerifier verifier;
            if (JWSAlgorithm.RS256.equals(algorithm) && key instanceof RSAKey rsaKey) {
                verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            } else if (JWSAlgorithm.ES256.equals(algorithm) && key instanceof ECKey ecKey) {
                verifier = new ECDSAVerifier(ecKey.toECPublicKey());
            } else {
                throw new ZentrauthAuthException("JWT signing key does not match its algorithm", 401);
            }

            if (!jwt.verify(verifier)) {
                throw new ZentrauthAuthException("JWT signature is invalid", 401);
            }
        } catch (JOSEException exception) {
            throw new ZentrauthAuthException("JWT signature could not be verified", 401, exception);
        }
    }

    private JWTClaimsSet readClaims(SignedJWT jwt) {
        try {
            return jwt.getJWTClaimsSet();
        } catch (ParseException exception) {
            throw new ZentrauthAuthException("JWT claims are malformed", 401, exception);
        }
    }

    private void validateClaims(JWTClaimsSet claims) {
        Date expiration = claims.getExpirationTime();
        if (expiration == null || !expiration.after(new Date())) {
            throw new ZentrauthAuthException("JWT is expired or has no expiration", 401);
        }
        if (!properties.getIssuerUri().equals(claims.getIssuer())) {
            throw new ZentrauthAuthException("JWT issuer is invalid", 401);
        }
    }

    private String readTenantId(JWTClaimsSet claims) {
        Object tenantClaim = claims.getClaim(TENANT_CLAIM);
        if (!(tenantClaim instanceof String tenantId) || tenantId.isBlank()) {
            throw new ZentrauthInvalidTenantException(TENANT_CLAIM + " claim is missing or invalid");
        }
        return tenantId;
    }
}
