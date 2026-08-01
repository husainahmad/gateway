package com.harmoni.gateway.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LoggingFilterTest {

    @Test
    void masksTokensInResponseBody() {
        String body = """
                {"accessToken":"eyJhbGciOiJIUzUxMiJ9.payload1.signature1","refreshToken":"eyJhbGciOiJIUzUxMiJ9.payload2.signature2"}""";

        String masked = LoggingFilter.maskSensitiveJsonFields(body);

        assertThat(masked).doesNotContain("eyJhbGciOiJIUzUxMiJ9");
        assertThat(masked).contains("\"accessToken\":\"[MASKED]\"");
        assertThat(masked).contains("\"refreshToken\":\"[MASKED]\"");
    }

    @Test
    void masksNestedSensitiveFields() {
        String body = """
                {"user":{"username":"kasir1","password":"hunter2"},"profile":{"roles":[]}}""";

        String masked = LoggingFilter.maskSensitiveJsonFields(body);

        assertThat(masked).doesNotContain("hunter2");
        assertThat(masked).contains("\"password\":\"[MASKED]\"");
        assertThat(masked).contains("kasir1");
        assertThat(masked).contains("\"roles\":[]");
    }

    @Test
    void leavesNonSensitiveFieldsUntouched() {
        String body = "{\"id\":14,\"name\":\"kasir1\",\"active\":true}";

        String masked = LoggingFilter.maskSensitiveJsonFields(body);

        assertThat(masked).isEqualTo(body);
    }

    @Test
    void masksWithRegexWhenJsonIsTruncated() {
        String body = "{\"accessToken\":\"eyJhbGciOiJIUzUxMiJ9.payload1.signature1\",\"refreshToken\":\"eyJhbGciOiJIUzUxMiJ9.payload2";

        String masked = LoggingFilter.maskSensitiveJsonFields(body);

        assertThat(masked).doesNotContain("eyJhbGciOiJIUzUxMiJ9.payload1");
        assertThat(masked).contains("\"accessToken\":\"[MASKED]\"");
        assertThat(masked).contains("\"refreshToken\":\"[MASKED]\"");
    }
}
