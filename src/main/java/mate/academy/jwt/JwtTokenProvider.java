package mate.academy.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {
    @Value("${security.jwt.token.secret-key:secret}")
    private String secretKey;
    @Value("${security.jwt.token.expire-length:3600000}")
    private long ttl;
    private  final UserDetailsService userDetailsService;

    public JwtTokenProvider(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String login, List<String> roles) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + ttl);
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            return JWT.create()
                    .withSubject(login)
                    .withClaim("roles", roles)
                    .withIssuedAt(now)
                    .withExpiresAt(validity)
                    .sign(algorithm);
        } catch (JWTCreationException e) {
            throw new RuntimeException("Can't create token with login: " + login
                    + "; and roles: " + roles, e);
        }
    }
    public boolean validateToken(String token) {
        if (token == null) {
            return false;
        }
        DecodedJWT jwt;
        try {
            Algorithm algorithm = Algorithm.HMAC256(secretKey);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            jwt = verifier.verify(token);
        } catch (JWTVerificationException exception){
            throw new InvalidJwtAuthenticationException("Can't authenticate with token: "
                    + token, exception);
        }
        Date now = new Date();
        return jwt.getExpiresAt().after(now);
    }

    public Authentication getAuthentication(String token) {
        String name = getName(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(name);
        return new UsernamePasswordAuthenticationToken(userDetails,
                userDetails.getPassword(),
                userDetails.getAuthorities());
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    private String getName(String token) {
        return JWT.decode(token).getSubject();
    }
}
