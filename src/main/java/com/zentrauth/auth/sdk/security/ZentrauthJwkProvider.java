package com.zentrauth.auth.sdk.security;

import com.nimbusds.jose.jwk.JWK;

public interface ZentrauthJwkProvider {
    JWK get(String keyId);
}
