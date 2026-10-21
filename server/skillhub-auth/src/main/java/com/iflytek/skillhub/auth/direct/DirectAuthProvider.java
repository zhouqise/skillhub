package com.iflytek.skillhub.auth.direct;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;

/**
 * Extension point for username/password style direct authentication sources.
 */
public interface DirectAuthProvider {
    default boolean enabled() { return true; }


    String providerCode();

    default String displayName() {
        return providerCode();
    }

    PlatformPrincipal authenticate(DirectAuthRequest request);
}
