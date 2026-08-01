package com.harmoni.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "harmoni.auth.jwt")
public record JwtProperties(String secret) {}
