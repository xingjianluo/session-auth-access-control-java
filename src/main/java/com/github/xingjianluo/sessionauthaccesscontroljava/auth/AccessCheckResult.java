package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

public sealed interface AccessCheckResult {

    record Valid(String sessionId, String username) implements AccessCheckResult {
    }

    enum Invalid implements AccessCheckResult {
        MISSING,
        MALFORMED,
        TAMPERED,
        EXPIRED,
        SESSION_REVOKED
    }
}
