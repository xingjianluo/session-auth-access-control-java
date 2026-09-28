package com.github.xingjianluo.sessionauthaccesscontroljava.token;

import java.time.Instant;

/** 凭证中携带的声明。 */
public record TokenClaims(
        TokenType type,
        String subject,
        String sessionId,
        String jti,
        Instant issuedAt,
        Instant expiresAt
) {
}
