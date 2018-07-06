package foosi.authapi.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static foosi.authapi.security.SecurityConstants.SIGN_UP_URL;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * primary configuration for the spring security
 *
 */
@Configuration
@EnableWebSecurity // custom configuration and disable the default setting and need to extend WebSecurityConfigurerAdapter
public class WebSecurity extends WebSecurityConfigurerAdapter {
	
	@Autowired
    private UserDetailsService userDetailsService;
	
	@Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

	// request layer configuration - HttpSecurity
	// 
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable().authorizeRequests()
        		// URL: /users/sign-up
                .antMatchers(HttpMethod.POST, SIGN_UP_URL).permitAll() // permit only sign up URL
                .antMatchers(HttpMethod.POST, "/welcome").permitAll()
                .antMatchers(HttpMethod.GET, "/welcome").permitAll()
                .antMatchers(HttpMethod.POST, "/").permitAll()
                .antMatchers(HttpMethod.GET, "/").permitAll()
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                .antMatchers("/dba/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_DBA')")
                .anyRequest().authenticated()
                .and()
                // authentication manager builder is already configured in method configure below
                // and used to create the authentication manager
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // this disables session creation on Spring Security
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                	.formLogin()
                		.loginPage("/auth/login")
                		//.failureUrl("/login?error")
                		.usernameParameter("loginId").passwordParameter("passwd")                	
                		.permitAll() // for custom login page
                //.and()
                //	.logout().logoutSuccessUrl("/login?logout")
                //.and()
                //	.csrf()
                ;
        
    }

    // Authentication layer configuration - AuthenticationManagerBuilder
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
    	
    	// 1. set the user details service which is used to return the user detail with name and the encoded password
    	// 2. tell the user details service that which password encoder is used
    	
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }
    
    // ************************************************************************************************
    // once the basic configuration is done, it is required to create the custom UserDetailsService
    // and also PermissionEvaluator if necessary 
    
    
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
	  auth.inMemoryAuthentication().withUser("test").password("123456").roles("USER");
	  auth.inMemoryAuthentication().withUser("admin").password("123456").roles("ADMIN");
	  auth.inMemoryAuthentication().withUser("dba").password("123456").roles("DBA");
	}    

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}
}