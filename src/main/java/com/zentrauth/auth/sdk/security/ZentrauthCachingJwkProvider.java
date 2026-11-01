package com.zentrauth.auth.sdk.security;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.zentrauth.auth.sdk.exception.ZentrauthAuthException;

public class ZentrauthCachingJwkProvider implements ZentrauthJwkProvider {
    private static final int MAX_JWKS_BYTES = 1_048_576;

    private final URI jwksUri;
    private final long cacheDurationNanos;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;
    private final Object refreshLock = new Object();
    private volatile CachedJwkSet cache;

    public ZentrauthCachingJwkProvider(
            String jwksUri,
            Duration cacheDuration,
            Duration connectTimeout,
            Duration readTimeout
    ) {
        this.jwksUri = URI.create(jwksUri);
        this.cacheDurationNanos = positiveDurationNanos(cacheDuration, "cacheDuration");
        this.connectTimeoutMillis = positiveTimeoutMillis(connectTimeout, "connectTimeout");
        this.readTimeoutMillis = positiveTimeoutMillis(readTimeout, "readTimeout");
    }

    @Override
    public JWK get(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            throw new ZentrauthAuthException("JWT is missing a key identifier", 401);
        }

        JWK key = getCachedSet(false).keySet().getKeyByKeyId(keyId);
        if (key == null) {
            key = getCachedSet(true).keySet().getKeyByKeyId(keyId);
        }
        if (key == null) {
            throw new ZentrauthAuthException("JWT signing key was not found", 401);
        }
        return key;
    }

    private CachedJwkSet getCachedSet(boolean forceRefresh) {
        CachedJwkSet current = cache;
        if (!forceRefresh && isFresh(current)) {
            return current;
        }

        synchronized (refreshLock) {
            current = cache;
            if (!forceRefresh && isFresh(current)) {
                return current;
            }
            cache = fetchJwks();
            return cache;
        }
    }

    private CachedJwkSet fetchJwks() {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) jwksUri.toURL().openConnection();
            connection.setConnectTimeout(connectTimeoutMillis);
            connection.setReadTimeout(readTimeoutMillis);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept", "application/json");

            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("JWKS endpoint returned HTTP " + status);
            }

            try (InputStream input = connection.getInputStream()) {
                byte[] content = input.readNBytes(MAX_JWKS_BYTES + 1);
                if (content.length > MAX_JWKS_BYTES) {
                    throw new IOException("JWKS response exceeds the maximum size");
                }
                JWKSet keySet = JWKSet.parse(new String(content, StandardCharsets.UTF_8));
                return new CachedJwkSet(keySet, System.nanoTime());
            }
        } catch (IOException | ParseException | IllegalArgumentException exception) {
            throw new ZentrauthAuthException("Unable to retrieve a valid JWKS", 503, exception);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private boolean isFresh(CachedJwkSet cached) {
        return cached != null && System.nanoTime() - cached.fetchedAtNanos() < cacheDurationNanos;
    }

    private record CachedJwkSet(JWKSet keySet, long fetchedAtNanos) {
    }

    private static long positiveDurationNanos(Duration duration, String name) {
        if (duration == null || duration.isZero() || duration.isNegative()) {
            throw new IllegalArgumentException(name + " must be a positive duration");
        }
        try {
            return duration.toNanos();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException(name + " is too large", exception);
        }
    }

    private static int positiveTimeoutMillis(Duration timeout, String name) {
        if (timeout == null || timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException(name + " must be a positive duration");
        }
        try {
            long timeoutMillis = timeout.toMillis();
            if (timeoutMillis < 1 || timeoutMillis > Integer.MAX_VALUE) {
                throw new IllegalArgumentException(name + " must be between 1 ms and "
                        + Integer.MAX_VALUE + " ms");
            }
            return (int) timeoutMillis;
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException(name + " is too large", exception);
        }
    }
}
