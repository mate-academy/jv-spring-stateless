package mate.academy.config;

import mate.academy.security.jwt.JwTokenProvider;
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
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final JwTokenProvider jwTokenProvider;

    public SecurityConfig(UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder, JwTokenProvider jwTokenProvider) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.jwTokenProvider = jwTokenProvider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/login", "/register")
                .permitAll()
                .antMatchers("/inject")
                .permitAll()
                .antMatchers(HttpMethod.GET, "/cinema-halls/**").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.POST, "/cinema-halls/**").hasAnyRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/movies/**").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.POST, "/movies/**").hasAnyRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/movie-sessions/**").hasAnyRole("ADMIN", "USER")
                .antMatchers(HttpMethod.POST, "/movie-sessions/**").hasAnyRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/movie-sessions/{id}").hasRole("ADMIN")
                .antMatchers(HttpMethod.GET, "/orders/**").hasRole("USER")
                .antMatchers(HttpMethod.POST, "/orders/**").hasRole("USER")
                .antMatchers(HttpMethod.GET, "/shopping-carts/**").hasRole("USER")
                .antMatchers(HttpMethod.PUT, "/shopping-carts/**").hasRole("USER")
                .antMatchers(HttpMethod.GET, "/users/**").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/**").hasRole("ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .apply(new JwtConfigurer(jwTokenProvider))
                .and()
                .headers().frameOptions().disable();
    }
}
