package com.myapp.fileservice.security.jwt;

import java.io.IOException;
import java.util.Map;

import javax.sql.DataSource;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import com.myapp.fileservice.multitenancy.TenantContextHolder;
import com.myapp.fileservice.security.services.UserDetailsServiceImpl;
import com.myapp.fileservice.dto.Dsource;
import com.myapp.fileservice.multitenancy.MultiTenancyJpaConfiguration;
import com.zaxxer.hikari.HikariDataSource;

public class AuthTokenFilter extends OncePerRequestFilter {
	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	
	@Autowired
	private Map<String, DataSource> dataSourcesMtApp;
	
	@Autowired
	private RestTemplate restTemplate;
	
	@Value("${tenant.service.api.get}")
	private String tenantGetApi;

	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String tenant = obtainTenantFromSubdomain(request);
			if(!dataSourcesMtApp.containsKey(tenant)) {
				HttpHeaders headers = new HttpHeaders();
				ResponseEntity<Dsource[]> tenantResponse = restTemplate.exchange(tenantGetApi, HttpMethod.GET,
						new HttpEntity<Object>(headers), Dsource[].class);
				boolean flag = true;
				if (tenantResponse.getBody() != null) {
					Dsource[] dsList = tenantResponse.getBody();
					if (dsList != null && dsList.length > 0) {
						for (Dsource d : dsList) {
							if (d.getTenantId().equalsIgnoreCase(tenant)) {
								DataSourceBuilder<?> factory = DataSourceBuilder.create(MultiTenancyJpaConfiguration.class.getClassLoader())
										.url(d.getUrl())
										.username(d.getUsername())
										.password(d.getPassword()).driverClassName(d.getDriverClassName());
								HikariDataSource ds = (HikariDataSource) factory.build();
								ds.setKeepaliveTime(40000);
								ds.setMinimumIdle(1);
								ds.setMaxLifetime(45000);
								ds.setIdleTimeout(35000);
								dataSourcesMtApp.put(tenant, ds);
								flag = false;
								break;
							}
						}
					}
				}
			}
			TenantContextHolder.setTenantId(tenant);
			String jwt = parseJwt(request);
			if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
				String username = jwtUtils.getUserNameFromJwtToken(jwt);

				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}

		filterChain.doFilter(request, response);
	}

	private String parseJwt(HttpServletRequest request) {
		String headerAuth = request.getHeader("Authorization");

		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			return headerAuth.substring(7);
		}

		return null;
	}

	private String obtainTenantFromSubdomain(HttpServletRequest request) {
		return request.getServerName().split("\\.")[0];
	}

}
