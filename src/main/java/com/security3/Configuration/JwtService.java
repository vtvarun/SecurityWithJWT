package com.security3.Configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {


    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        return claims.get("name",String.class);
    }

    public Date extractExpiration(String token) {
        return extractAllClaims(token).getExpiration();
    }


    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }


    public String createToken(String username){
        Map<String,Object> claims = new HashMap<>();
        claims.put("name",username);
        return createTokenMethod(claims);
    }

    private String createTokenMethod(Map<String, Object> claims) {
        return Jwts.builder().setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() * 1000 * 60 * 30))
                .signWith(getSignKey(),SignatureAlgorithm.HS256).compact();
    }

    private Key getSignKey() {
        byte[] byteKeys = Decoders.BASE64.decode("cc7728f9fa185793089070bf3d0429ce769be7d679bb5a26f250347d0ebd95516b0815f462f6963f56e17651f9d0af2db46b29e2bd571152d4dc5ccbf96063194229ccb4158bc21915b846d69e77d4ee80aae350fa0cf33c58a9a4ddf9fd34d0d9306a75f92090ffcb6b87cc9d69341aaaf451619b1e80fc55a18552d9181fe250a264814445911d951367b8bc8da20dc42c2301ade37321903e5b5a3f9057cf319efb3e926bd6ef260176089d102814c980dd9ef8ddfad1ae7198129c461e07cb2b0d330c9e666c7ba7ad34dfb18a2db904fb08c2e6a933664bd4fe5be721e388d119671cb398a99e771feed93b2039bd3f3ad030ba86c6e677d27595df5199");
        return Keys.hmacShaKeyFor(byteKeys);
    }


}
