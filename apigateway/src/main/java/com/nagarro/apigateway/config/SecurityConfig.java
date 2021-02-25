package com.nagarro.apigateway.config;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.nagarro.apigateway.component.JWTComponentFilter;
import com.nagarro.apigateway.constants.CommonConstants;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private JWTComponentFilter jwtComponentFilter;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				.formLogin().disable()
				.logout().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.exceptionHandling()
				.authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
				.and()
				.addFilterBefore(jwtComponentFilter, UsernamePasswordAuthenticationFilter.class)
				.authorizeRequests()
				.antMatchers("/user-management/user/login").permitAll()
				.antMatchers("/product-catalogue/services/addUpdateService").hasRole(CommonConstants.PRODUCER)
				.antMatchers("/order-management/producer/**").hasRole(CommonConstants.PRODUCER)
				.antMatchers("/order-management/admin/**").hasRole(CommonConstants.PRODUCER)
				.anyRequest().authenticated();
	}

}
