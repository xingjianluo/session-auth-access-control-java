package com.github.xingjianluo.sessionauthaccesscontroljava.security;

/** 续期结论：覆盖篡改、过期、撤销、重复使用、已退出及被限流等可区分情形。 */
public enum RefreshResult {
    SUCCESS,
    MALFORMED,
    BAD_SIGNATURE,
    EXPIRED,
    WRONG_TYPE,
    SESSION_NOT_FOUND,
    REVOKED,
    REUSED,
    LOGGED_OUT,
    ACCOUNT_DISABLED,
    RATE_LIMITED
}
