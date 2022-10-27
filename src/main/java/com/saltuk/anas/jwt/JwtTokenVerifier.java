package com.saltuk.anas.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");

        if(Strings.isNullOrEmpty(authorization) || !authorization.startsWith("Bearer ")) {
//            filterChain.doFilter(request, response);
        }

        String token = authorization.replace("Bearer ", "");
        try {
            var key = "securesecuresecuresecuresecuresecuresecure";
            Jws<Claims> jws = Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(key.getBytes(StandardCharsets.UTF_8)))
                    .parseClaimsJws(token);
            Claims body = jws.getBody();
            String username = body.getSubject();
            var authorities = (List<Map<String, String>>) body.get("authorities");

            var auths = authorities.stream().map(a -> new SimpleGrantedAuthority(a.get("authority"))).collect(Collectors.toSet());

            var authentication = new UsernamePasswordAuthenticationToken(username, null, auths);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e) {
            e.printStackTrace();
            throw new IllegalStateException("Token "+  token + "cannot be trusted");
        }
        filterChain.doFilter(request, response);
    }
}
