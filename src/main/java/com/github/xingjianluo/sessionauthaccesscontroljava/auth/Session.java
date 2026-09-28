package com.github.xingjianluo.sessionauthaccesscontroljava.auth;

import java.time.Instant;

public record Session(
        String sessionId,
        String username,
        Instant createdAt,
        Instant refreshExpiresAt,
        String currentRefreshTokenHash,
        boolean revoked) {
}
