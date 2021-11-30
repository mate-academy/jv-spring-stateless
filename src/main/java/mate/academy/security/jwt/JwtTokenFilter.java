package mate.academy.security.jwt;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class JwtTokenFilter extends GenericFilterBean {
    private final JwtTokenPRovider jwtTokenPRovider;

    public JwtTokenFilter(JwtTokenPRovider jwtTokenPRovider) {
        this.jwtTokenPRovider = jwtTokenPRovider;
    }

    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain)
            throws IOException, ServletException {
        String token = jwtTokenPRovider.resolveToken((HttpServletRequest) servletRequest);
        if (token != null && jwtTokenPRovider.validateToken(token)) {
            Authentication authentication = jwtTokenPRovider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
