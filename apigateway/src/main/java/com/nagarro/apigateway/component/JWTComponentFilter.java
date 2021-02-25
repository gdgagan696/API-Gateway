package com.nagarro.apigateway.component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nagarro.apigateway.constants.JwtConstants;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JWTComponentFilter extends OncePerRequestFilter {

	private static final Logger LOG = LoggerFactory.getLogger(JWTComponentFilter.class);

	@SuppressWarnings("unchecked")
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		LOG.debug("Inside token validation");

		final String authorizationHeader = request.getHeader(JwtConstants.HEADER);
		String userName = null;
		List<String> authorities=new ArrayList<>();
		if (!StringUtils.isEmpty(authorizationHeader) && authorizationHeader.startsWith(JwtConstants.HEADER_PREFIX)) {
			String jwtToken = authorizationHeader.substring(7);
			Claims claims = Jwts.parser().setSigningKey(JwtConstants.SECRET).parseClaimsJws(jwtToken).getBody();
			userName = claims.getSubject();
			authorities=(List<String>) claims.get("authorities");

		}
		if (!StringUtils.isEmpty(userName) && SecurityContextHolder.getContext().getAuthentication() == null) {
			UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
					userName, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
			SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
		}

		filterChain.doFilter(request, response);

	}

}
