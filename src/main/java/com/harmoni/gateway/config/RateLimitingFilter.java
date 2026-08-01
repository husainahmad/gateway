package com.harmoni.gateway.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private final int maxRequests;
    private final long windowMillis;
    private final ConcurrentMap<String, ClientBucket> clients = new ConcurrentHashMap<>();

    public RateLimitingFilter(
            @Value("${harmoni.gateway.rate-limit.max-requests:100}") int maxRequests,
            @Value("${harmoni.gateway.rate-limit.window-seconds:60}") int windowSeconds) {
        this.maxRequests = maxRequests;
        this.windowMillis = windowSeconds * 1000L;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String clientIp = resolveClientIp(request);

        ClientBucket bucket = clients.compute(clientIp, (key, existing) -> {
            long now = System.currentTimeMillis();
            if (existing == null || now - existing.windowStart >= windowMillis) {
                return new ClientBucket(1, now);
            }
            existing.count++;
            return existing;
        });

        if (bucket.count > maxRequests) {
            log.warn("Rate limit exceeded for IP={}, count={}/{}", clientIp, bucket.count, maxRequests);
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Too Many Requests\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private static String resolveClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static class ClientBucket {
        int count;
        long windowStart;

        ClientBucket(int count, long windowStart) {
            this.count = count;
            this.windowStart = windowStart;
        }
    }
}
