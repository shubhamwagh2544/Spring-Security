package com.springboot2.security.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;
    private final JwtSecretKey secretKey;

    public JwtTokenVerifier(JwtConfig jwtConfig, JwtSecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey.secretKey())
                    .parseClaimsJws(jwtToken);

            Claims body = claimsJws.getBody();

            String username = body.getSubject();    //username :> admin

            //adminJwtToken
            /*
                    "authorities": [
                            {
                              "authority": "student:write"
                            },
                            {
                              "authority": "student:read"
                            },
                            {
                              "authority": "course:read"
                            },
                            {
                              "authority": "ROLE_ADMIN"
                            },
                            {
                              "authority": "course:write"
                            }
                    ]
             */

            var authorities =(List<Map<String, String>>) body.get("authorities");

            Set<SimpleGrantedAuthority> grantedAuthorities =
                    authorities.stream()
                    .map(entry -> new SimpleGrantedAuthority(entry.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    grantedAuthorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", jwtToken));
        }

        //response should be carried to the end API through filters
        filterChain.doFilter(request, response);

    }

}
