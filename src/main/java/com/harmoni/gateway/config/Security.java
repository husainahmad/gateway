package com.harmoni.gateway.config;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class Security {

    private final JwtProperties jwtProperties;

    Security(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            CorsConfigurationSource corsConfigurationSource,
                                            LoggingFilter loggingFilter,
                                            RateLimitingFilter rateLimitingFilter)
            throws Exception {

        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(loggingFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new OncePerRequestFilter() {
                    @Override
                    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
                        // Extract JWT token from the request header
                        String authToken = request.getHeader("Authorization");

                        if (authToken != null && authToken.startsWith("Bearer ")) {
                            try {
                                // Parse the token to extract username and roles
                                String token = authToken.substring(7); // Remove "Bearer " prefix
                                Claims claims = parseToken(token);
                                String username = claims.getSubject();

                                Object rolesClaim = claims.get("roles");
                                String roles = rolesClaim == null ? "" : rolesClaim.toString();

                                Object userIdClaim = claims.get("userId");
                                String userId = userIdClaim == null ? "" : userIdClaim.toString();

                                filterChain.doFilter(new HeaderAddingRequestWrapper(request,
                                        "X-Username", username,
                                        "X-User-Id", userId,
                                        "X-Roles", roles), response);
                                return;

                            } catch (Exception e) {
                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
                                return;
                            }
                        }

                        filterChain.doFilter(request, response);
                    }

                    private Claims parseToken(String token) {
                        return Jwts.parserBuilder()
                                .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.secret())))
                                .build()
                                .parseClaimsJws(token)
                                .getBody();
                    }
                }, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    static final class HeaderAddingRequestWrapper extends HttpServletRequestWrapper {

        private final Map<String, String> headersToAdd;

        HeaderAddingRequestWrapper(HttpServletRequest request, String... headerKeyValues) {
            super(request);
            if (headerKeyValues.length % 2 != 0) {
                throw new IllegalArgumentException("headerKeyValues must contain key/value pairs");
            }
            this.headersToAdd = new LinkedHashMap<>();
            for (int i = 0; i < headerKeyValues.length; i += 2) {
                headersToAdd.put(headerKeyValues[i], headerKeyValues[i + 1]);
            }
        }

        @Override
        public String getHeader(String name) {
            String value = headersToAdd.get(name);
            return value != null ? value : super.getHeader(name);
        }

        @Override
        public Enumeration<String> getHeaders(String name) {
            if (headersToAdd.containsKey(name)) {
                return Collections.enumeration(Collections.singletonList(headersToAdd.get(name)));
            }
            return super.getHeaders(name);
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            Set<String> names = new LinkedHashSet<>(Collections.list(super.getHeaderNames()));
            names.addAll(headersToAdd.keySet());
            return Collections.enumeration(names);
        }
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // Permissive defaults — tighten allowed origins per environment before production.
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("X-Username", "X-User-Id", "X-Roles"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}