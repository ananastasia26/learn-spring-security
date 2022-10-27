package com.saltuk.anas.jwt;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Configuration
public class JwtKeyConfiguration {
    private final JwtConfiguration jwtConfiguration;

    public JwtKeyConfiguration(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }

    @Bean
    public SecretKey getKey() {
        return Keys.hmacShaKeyFor(jwtConfiguration.getKey().getBytes(StandardCharsets.UTF_8));
    }
}
