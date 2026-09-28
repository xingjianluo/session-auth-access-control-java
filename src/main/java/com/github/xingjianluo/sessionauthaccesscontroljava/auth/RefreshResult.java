package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

public sealed interface RefreshResult {

    record Success(TokenPair tokens) implements RefreshResult {
    }

    enum Failure implements RefreshResult {
        TAMPERED,
        EXPIRED,
        REVOKED,
        REUSED,
        RATE_LIMITED
    }
}
