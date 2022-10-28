package mate.academy.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import mate.academy.exception.InvalidJwtAuthenticationException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {
    private static final int START_INDEX_OF_TOKEN = 7;

    @Value("${security.jwt.token.secret-key:secret}")
    private String secreteKey;
    @Value("${security.jwt.token.expire-length:360000}")
    private long validityInMilliSeconds;
    private final UserDetailsService service;

    public JwtTokenProvider(UserDetailsService service) {
        this.service = service;
    }

    @PostConstruct
    protected void init() {
        secreteKey = Base64.getEncoder().encodeToString(secreteKey.getBytes());
    }

    public String createToken(String login, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(login);
        claims.put("roles", roles);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliSeconds);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secreteKey)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        UserDetails details = service.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(details, details.getAuthorities());
    }

    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secreteKey).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(START_INDEX_OF_TOKEN);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secreteKey).parseClaimsJws(token);
            return !claimsJws.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException("Token doesn't valid!", e);
        }
    }
}
