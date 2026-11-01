# zentrauth-auth-spring-boot-starter Technical Specification & Developer Scaffolding Prompt

## 1. Executive Summary & Overview

`zentrauth-auth-spring-boot-starter` (Maven Group: `com.zentrauth`, Artifact ID: `zentrauth-auth-spring-boot-starter`) is the official client-side SDK for integrating customer microservices with the **ZentrAuth** Multi-Tenant IAM Platform (`zentrauth.com`).

It enables zero-network stateless JWT verification (<5ms runtime overhead), automatically extracts multi-tenant context (`zentrauth_tenant_id`), populates Spring Security's `Authentication` context, and binds tenant state for downstream operations (such as PostgreSQL Row-Level Security).

## 2. Target Project Metadata & Structure

### Maven Coordinates

* **GroupId:** `com.zentrauth`
* **ArtifactId:** `zentrauth-auth-spring-boot-starter`
* **Version:** `1.0.0-SNAPSHOT`
* **Java Version:** 17+ (LTS target, Java 21 compatible)
* **Spring Boot Version:** 3.x+

### Package Structure

```
com.zentrauth.auth.sdk
├── autoconfigure
│   ├── ZentrauthAuthAutoConfiguration.java
│   └── ZentrauthAuthProperties.java
├── context
│   ├── ZentrauthTenantContext.java
│   └── ZentrauthTenantContextHolder.java
├── exception
│   ├── ZentrauthAuthException.java
│   └── ZentrauthInvalidTenantException.java
├── filter
│   └── ZentrauthTenantSecurityFilter.java
└── security
    ├── ZentrauthCachingJwkProvider.java
    └── ZentrauthJwkProvider.java
```

## 3. Core Component Contracts & Specs

### 3.1 ZentrauthTenantContextHolder

Thread-bound multi-tenant state for the duration of an HTTP request.

```java
package com.zentrauth.auth.sdk.context;

public class ZentrauthTenantContextHolder {
    private static final ThreadLocal<ZentrauthTenantContext> CONTEXT = new ThreadLocal<>();

    public static void setContext(ZentrauthTenantContext zentrauthTenantContext) {
        CONTEXT.set(zentrauthTenantContext);
    }

    public static ZentrauthTenantContext getContext() {
        return CONTEXT.get();
    }

    public static String getZentrauthTenantId() {
        ZentrauthTenantContext ctx = CONTEXT.get();
        return ctx != null ? ctx.getZentrauthTenantId() : null;
    }

    public static void clear() {
        CONTEXT.remove();
    }
}
```

### 3.2 ZentrauthTenantSecurityFilter Requirements

1. **Filter Position:** Must execute *before* `UsernamePasswordAuthenticationFilter`.
2. **Key Caching:** Fetch and cache public JWKS keys from `https://auth.zentrauth.com/.well-known/jwks.json` using `ZentrauthCachingJwkProvider` (nimbus-jose-jwt under the hood with a 15-minute TTL cache).
3. **Validation Sequence:**
   * Extract Bearer token from `Authorization` header.
   * Verify token signature, expiration (`exp`), and issuer (`iss: https://auth.zentrauth.com`).
   * Extract `zentrauth_tenant_id` claim from verified JWT payload.
   * Optionally cross-check against incoming `ZentrAuth-Tenant-ID` header if present (throw `ZentrauthInvalidTenantException` on mismatch or missing claim).
   * Bind `ZentrauthTenantContext` to `ZentrauthTenantContextHolder`.
   * Populate `SecurityContextHolder`.
4. **Cleanup:** Guarantee `ZentrauthTenantContextHolder.clear()` execution inside a mandatory `finally` block to prevent `ThreadLocal` memory leaks across thread pools.

## 4. Configuration Specification (`application.yml`)

Spring properties exposed by `ZentrauthAuthProperties`:

```yaml
zentrauth:
  auth:
    enabled: true
    issuer-uri: "https://auth.zentrauth.com"
    jwks-uri: "https://auth.zentrauth.com/.well-known/jwks.json"
    tenant-header: "ZentrAuth-Tenant-ID"
    excluded-paths:
      - "/actuator/health"
      - "/public/**"
      - "/swagger-ui/**"
      - "/v3/api-docs/**"
```

### Auto-Configuration Marker

File path: `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`

```text
com.zentrauth.auth.sdk.autoconfigure.ZentrauthAuthAutoConfiguration
```

## 5. Security & Isolation Rules

1. **Fail-Closed:** If JWKS endpoint is unreachable and no valid key is cached, reject requests with `503 Service Unavailable` or `401 Unauthorized`.
2. **Anti-Spoofing:** Never trust unverified HTTP headers (`ZentrAuth-Tenant-ID`) without validating them against cryptographically signed claims inside the JWT.
3. **Database RLS Hook:** Persistence layers access `ZentrauthTenantContextHolder.getZentrauthTenantId()` to execute `SET LOCAL app.current_zentrauth_tenant_id = 'zentrauth_tenant_xyz'` per transaction context.

## 6. Scaffolding Prompt for AI Assistants (Cursor / Copilot Workspace)

> "Act as a Senior Principal Java Engineer. Read the specification in `sdk_spec.md`. Scaffold the entire `zentrauth-auth-spring-boot-starter` repository under package `com.zentrauth.auth.sdk`. Create `ZentrauthTenantContext`, `ZentrauthTenantContextHolder`, `ZentrauthTenantSecurityFilter`, `ZentrauthAuthAutoConfiguration`, `ZentrauthAuthProperties`, `ZentrauthInvalidTenantException`, `ZentrauthJwkProvider`, and `ZentrauthCachingJwkProvider`. Include full unit tests with JUnit 5 and Mockito validating token verification, tenant header mismatch handling, and ThreadLocal context cleanup."