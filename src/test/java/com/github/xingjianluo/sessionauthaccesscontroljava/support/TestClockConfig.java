package com.github.xingjianluo.sessionauthaccesscontroljava.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.time.Clock;
import java.time.Instant;

/** 用可控时钟替换生产时钟，时间起点固定，测试间通过重置保持确定性。 */
@TestConfiguration
public class TestClockConfig {

    public static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

    @Bean
    @Primary
    public Clock mutableClock() {
        return new MutableClock(START);
    }
}
