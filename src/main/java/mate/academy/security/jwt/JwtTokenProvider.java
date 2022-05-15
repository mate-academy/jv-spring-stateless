package mate.academy.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Objects;
import java.util.Set;
import javax.annotation.PostConstruct;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import mate.academy.exception.InvalidJwtAuthenticationException;
import mate.academy.model.Role;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {
    private SecretKey secretKey;
    private long validityTimeInMilliseconds;
    private final Environment environment;
    private final UserDetailsService userDetailsService;

    public JwtTokenProvider(Environment environment,
                            UserDetailsService userDetailsService) {
        this.environment = environment;
        this.userDetailsService = userDetailsService;
    }

    @PostConstruct
    protected void init() {
        secretKey = Keys.hmacShaKeyFor(getSecretKey().getBytes(StandardCharsets. UTF_8));
        validityTimeInMilliseconds = getValidityTimeInMilliseconds();
    }

    public String createToken(String login, Set<Role> roles) {
        Claims claims = Jwts.claims().setSubject(login);
        claims.put("roles", roles);
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityTimeInMilliseconds);
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(secretKey).build()
                    .parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception ex) {
            throw new InvalidJwtAuthenticationException("Expired or invalid JWT token", ex);
        }
    }

    public Authentication getAuthentication(String token) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "",
                userDetails.getAuthorities());
    }

    private String getUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(secretKey).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    private long getValidityTimeInMilliseconds() {
        try {
            return Long.parseLong(Objects.requireNonNull(
                    environment.getProperty("JWT.validityTimeInMilliseconds")));
        } catch (NullPointerException | NumberFormatException ex) {
            throw new RuntimeException("Empty or wrong JWT.validityTimeInMilliseconds "
                    + "properties!", ex);
        }
    }

    private String getSecretKey() {
        try {
            return Objects.requireNonNull(environment.getProperty("JWT.secretKey"));
        } catch (NullPointerException ex) {
            throw new RuntimeException("Empty JWT.secretKey properties!", ex);
        }
    }
}
