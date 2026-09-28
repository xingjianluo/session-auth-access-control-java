package com.github.xingjianluo.sessionauthaccesscontroljava.security;

/** 登录结论，和凭证校验结论一样要求可区分。 */
public enum LoginResult {
    SUCCESS,
    INVALID_CREDENTIALS,
    ACCOUNT_DISABLED,
    RATE_LIMITED
}
