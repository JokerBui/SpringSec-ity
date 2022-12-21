package com.example.demo.security.jwt;

import com.example.demo.security.userprincal.UserPrinciciple;
import io.jsonwebtoken.*;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Component
public class JwtProvider {
    private static final Logger logger = (Logger) LoggerFactory.getLogger(JwtProvider.class);

    private String jwtSecret = "secretKeysecretKeysecretKeysecretKeysecretKeyKeysecretKeysecretKeysecretKeysecretKeysecretKeysecretKeyKeysecretKeysecretKey";

    private int jwtExpiration = 86400;
    public String createToken(Authentication authentication){
        Map<String, Object> claims = new HashMap<>();

        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();

        if (roles.contains(new SimpleGrantedAuthority("ADMIN"))) {
            claims.put("isAdmin", true);
        }

        UserPrinciciple userPrinciciple = (UserPrinciciple) authentication.getPrincipal();
        return Jwts.builder().setClaims(claims)
                .setSubject(userPrinciciple.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime()+jwtExpiration*1000))
                .signWith(SignatureAlgorithm.HS512,jwtSecret)

                .compact();
    }
    public boolean validateToken (String token){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        }catch (SignatureException e){

            logger.error("Invalid JWT signature ->Message: {} ",e);
        }catch (MalformedJwtException e){
            logger.error("Invalid JWT token ->Message: {} ",e);
        }catch (ExpiredJwtException e) {
            logger.error("Expored JWT token ->Message: {} ", e);
        }catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token ->Message: {} ", e);
        }catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty ->Message: {} ", e);
        }
        return false;
    }
    public String getUserNameFromToken(String token){
        String userName = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
        return userName;
    }

}
