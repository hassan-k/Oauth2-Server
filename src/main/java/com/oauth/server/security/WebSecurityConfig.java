package com.oauth.server.security;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;



@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
  /*  @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManager();
    } */

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
       
		http
			.authorizeRequests()
				.antMatchers("/oauth/token/**").permitAll()		
				.antMatchers("/tokens/**").permitAll()		
			.anyRequest().authenticated()
			.and()
			.csrf().disable();			   
	}   
}
