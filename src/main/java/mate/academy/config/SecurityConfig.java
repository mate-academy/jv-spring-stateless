package mate.academy.config;

import mate.academy.model.Role;
import mate.academy.security.jwt.JwtConfigurer;
import mate.academy.security.jwt.JwtTokenProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String ADMIN = Role.RoleName.ADMIN.name();
    private static final String USER = Role.RoleName.USER.name();
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public SecurityConfig(UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder,
                          JwtTokenProvider jwtTokenProvider) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/register", "/login").permitAll()
                .antMatchers(HttpMethod.GET, "/inject").permitAll()
                .antMatchers(HttpMethod.GET, "/", "/products").hasAnyRole(USER, ADMIN)
                .antMatchers(HttpMethod.GET, "/users").hasRole(ADMIN)
                .antMatchers(HttpMethod.POST, "/users").hasRole(ADMIN)
                .antMatchers(HttpMethod.DELETE, "/products/*", "/users/*").hasRole(ADMIN)
                .anyRequest()
                .authenticated()
                .and()
                .apply(new JwtConfigurer(jwtTokenProvider))
                .and()
                .httpBasic();
    }
}
