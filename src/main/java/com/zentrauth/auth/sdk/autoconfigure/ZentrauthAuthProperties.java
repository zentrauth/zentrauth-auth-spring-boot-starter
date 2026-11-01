package com.zentrauth.auth.sdk.autoconfigure;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "zentrauth.auth")
public class ZentrauthAuthProperties {
    private boolean enabled = true;
    private String issuerUri = "https://auth.zentrauth.com";
    private String jwksUri = "https://auth.zentrauth.com/.well-known/jwks.json";
    private Duration jwksCacheDuration = Duration.ofMinutes(15);
    private Duration jwksConnectTimeout = Duration.ofSeconds(3);
    private Duration jwksReadTimeout = Duration.ofSeconds(3);
    private String tenantHeader = "ZentrAuth-Tenant-ID";
    private List<String> excludedPaths = new ArrayList<>(List.of(
            "/actuator/health",
            "/public/**",
            "/swagger-ui/**",
            "/v3/api-docs/**"
    ));

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getIssuerUri() {
        return issuerUri;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public Duration getJwksCacheDuration() {
        return jwksCacheDuration;
    }

    public void setJwksCacheDuration(Duration jwksCacheDuration) {
        this.jwksCacheDuration = jwksCacheDuration;
    }

    public Duration getJwksConnectTimeout() {
        return jwksConnectTimeout;
    }

    public void setJwksConnectTimeout(Duration jwksConnectTimeout) {
        this.jwksConnectTimeout = jwksConnectTimeout;
    }

    public Duration getJwksReadTimeout() {
        return jwksReadTimeout;
    }

    public void setJwksReadTimeout(Duration jwksReadTimeout) {
        this.jwksReadTimeout = jwksReadTimeout;
    }

    public String getTenantHeader() {
        return tenantHeader;
    }

    public void setTenantHeader(String tenantHeader) {
        this.tenantHeader = tenantHeader;
    }

    public List<String> getExcludedPaths() {
        return excludedPaths;
    }

    public void setExcludedPaths(List<String> excludedPaths) {
        this.excludedPaths = new ArrayList<>(excludedPaths);
    }
}
