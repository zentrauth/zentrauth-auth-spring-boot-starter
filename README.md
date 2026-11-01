# ZentrAuth Auth Spring Boot Starter

Spring Boot 3 starter for verifying ZentrAuth bearer tokens and binding the verified `zentrauth_tenant_id` claim to the current request thread.

## Requirements

- Java 17 or newer
- Spring Boot 3.x

## Add the dependency

```groovy
implementation 'com.zentrauth:zentrauth-auth-spring-boot-starter:1.0.0-SNAPSHOT'
```

For Maven consumers:

```xml
<dependency>
    <groupId>com.zentrauth</groupId>
    <artifactId>zentrauth-auth-spring-boot-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Configure

```yaml
zentrauth:
  auth:
    enabled: true
    issuer-uri: "https://auth.zentrauth.com"
    jwks-uri: "https://auth.zentrauth.com/.well-known/jwks.json"
    jwks-cache-duration: 15m
    jwks-connect-timeout: 3s
    jwks-read-timeout: 3s
    tenant-header: "ZentrAuth-Tenant-ID"
    excluded-paths:
      - "/actuator/health"
      - "/public/**"
      - "/swagger-ui/**"
      - "/v3/api-docs/**"
```

The starter provides a stateless security chain when the application has not declared its own `SecurityFilterChain`. That default chain permits the configured excluded paths and requires an authenticated bearer token elsewhere.

If your application declares its own security chain, add the starter filter before Spring Security's username/password filter:

```java
http.addFilterBefore(zentrauthTenantSecurityFilter, UsernamePasswordAuthenticationFilter.class);
```

Inject `ZentrauthTenantSecurityFilter` into that chain configuration. The starter disables servlet-container registration so the filter does not run twice.

## Request behavior

Protected requests must provide a Bearer JWT in the `Authorization` header. The filter validates the JWT signature (RS256 or ES256), expiration, configured issuer, and non-empty `zentrauth_tenant_id` claim. JWKS data is cached for the configured `jwks-cache-duration` (default `15m`); JWKS connection and read timeouts default to `3s`. Spring Boot duration formats such as `15m`, `30s`, and `500ms` are supported. A supplied `ZentrAuth-Tenant-ID` header must exactly match the verified claim; otherwise the request receives HTTP 403. Authentication failures receive HTTP 401, while an unavailable or invalid JWKS endpoint receives HTTP 503.

During the downstream request, use `ZentrauthTenantContextHolder.getZentrauthTenantId()` to access the authenticated tenant. The holder is cleared in a `finally` block after the request. Persistence layers can use this value for their tenant-scoped database policy, such as `SET LOCAL app.current_zentrauth_tenant_id = ...` within a transaction.

## Build

```shell
gradlew.bat test
```
