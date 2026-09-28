package com.github.xingjianluo.sessionauthaccesscontroljava.security;

/** 续期结果：结论 + 成功时的新凭证对。 */
public record RefreshOutcome(RefreshResult result, TokenPair tokens) {

    public static RefreshOutcome of(RefreshResult result) {
        return new RefreshOutcome(result, null);
    }
}
