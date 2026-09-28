package com.github.xingjianluo.sessionauthaccesscontroljava;

import com.github.xingjianluo.sessionauthaccesscontroljava.config.RateLimitProperties;
import com.github.xingjianluo.sessionauthaccesscontroljava.config.TokenProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.time.Clock;

@SpringBootApplication
@EnableConfigurationProperties({TokenProperties.class, RateLimitProperties.class})
public class Application {

    /** 统一时钟，生产用 UTC 系统时钟；测试可替换为可控时钟。 */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
