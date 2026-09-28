package com.github.xingjianluo.sessionauthaccesscontroljava.security;

/** 访问凭证不被接受的原因，未登录 / 凭证问题 / 会话问题 / 账号问题可区分。 */
public enum AccessInvalidReason {
    MALFORMED,
    BAD_SIGNATURE,
    EXPIRED,
    WRONG_TYPE,
    SESSION_NOT_FOUND,
    LOGGED_OUT,
    REVOKED,
    ACCOUNT_DISABLED
}
