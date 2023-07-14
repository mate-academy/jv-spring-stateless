package mate.academy.config;

import mate.academy.model.Role;
import mate.academy.security.jwt.JwtConfigurer;
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
    private static final String ROLE_ADMIN = Role.RoleName.ADMIN.name();

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwtConfigurer jwtConfigurer;

    public SecurityConfig(UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder,
                          JwtConfigurer jwtConfigurer) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwtConfigurer = jwtConfigurer;
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
                .httpBasic().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
                .authorizeRequests()
                .antMatchers("/register", "/login", "/inject").permitAll()
                .antMatchers(HttpMethod.DELETE).hasRole(ROLE_ADMIN)
                .anyRequest().authenticated().and()
                .apply(jwtConfigurer);
    }
}
