package com.harmoni.gateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class HeaderAddingRequestWrapperTest {

    @Test
    void addsHeadersToForwardedRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer token");

        var wrapped = new Security.HeaderAddingRequestWrapper(request,
                "X-Username", "kasir1",
                "X-User-Id", "14",
                "X-Roles", "[]");

        assertThat(wrapped.getHeader("X-Username")).isEqualTo("kasir1");
        assertThat(wrapped.getHeader("X-User-Id")).isEqualTo("14");
        assertThat(wrapped.getHeader("X-Roles")).isEqualTo("[]");

        List<String> names = Collections.list(wrapped.getHeaderNames());
        assertThat(names).contains("X-Username", "X-User-Id", "X-Roles", "Authorization");

        assertThat(Collections.list(wrapped.getHeaders("X-Username"))).containsExactly("kasir1");
    }

    @Test
    void rejectsOddNumberOfArguments() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThatIllegalArgumentException().isThrownBy(() ->
                new Security.HeaderAddingRequestWrapper(request, "X-Username"));
    }
}
