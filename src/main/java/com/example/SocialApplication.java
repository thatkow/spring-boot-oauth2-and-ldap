package com.example;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.encoding.LdapShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.CompositeFilter;

@SpringBootApplication
@EnableOAuth2Client
@EnableAuthorizationServer
@Configuration
@Service
public class SocialApplication extends WebSecurityConfigurerAdapter {

	private static final String AFTER_LOGIN_URL = "/home";
	private static final String LOGIN_URL = "/login";

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// /send-pin /check-pin As recommended on
		// http://stackoverflow.com/questions/37241354/http-status-403-invalid-csrf-token-9ee6949c-c5dc-4d4b-9d55-46b75abc2994-was

		http.authorizeRequests()
				.antMatchers("/login**", "/login/github", "/webjars/**", "/static/**", "/img/*", "/css/*", "/send-pin",
						"/check-pin")
				.permitAll().and().authorizeRequests().anyRequest().fullyAuthenticated().and().exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_URL)).and().csrf()
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
				.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class).formLogin()
				.defaultSuccessUrl(AFTER_LOGIN_URL, true).and().logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl(LOGIN_URL);
		;
	}

	/*
	 * OAuth2
	 */
	@Autowired
	OAuth2ClientContext oauth2ClientContext;

	@Bean(name = "github")
	@ConditionalOnProperty(name = "github.client.clientId")
	@ConditionalOnExpression("'${github.client.clientId}' != ''")
	@ConfigurationProperties("github")
	public ClientResources github() {
		return new ClientResources();
	}

	@Bean(name = "facebook")
	@ConditionalOnProperty(name = "facebook.client.clientId")
	@ConditionalOnExpression("'${facebook.client.clientId}' != ''")
	@ConfigurationProperties("facebook")
	public ClientResources facebook() {
		return new ClientResources();
	}

	@Bean(name = "google")
	@ConditionalOnProperty(name = "google.client.clientId")
	@ConditionalOnExpression("'${google.client.clientId}' != ''")
	@ConfigurationProperties("google")
	public ClientResources google() {
		return new ClientResources();
	}

	@Autowired(required = false)
	@Qualifier("facebook")
	private ClientResources facebookClientResource;

	@Autowired(required = false)
	@Qualifier("google")
	private ClientResources googleClientResource;

	@Autowired(required = false)
	@Qualifier("github")
	private ClientResources githubClientResource;

	/*
	 * OAuth2 Methods
	 */
	private Filter ssoFilter() {
		CompositeFilter filter = new CompositeFilter();
		List<Filter> filters = new ArrayList<Filter>();
		addIfNotNull(filters, facebookClientResource, "/login/facebook");
		addIfNotNull(filters, githubClientResource, "/login/github");
		addIfNotNull(filters, googleClientResource, "/login/google");
		filter.setFilters(filters);
		return filter;
	}

	private void addIfNotNull(List<Filter> filters, ClientResources clientResource, String path) {
		if (clientResource != null) {
			Filter ssoFilterSingle = ssoFilter(clientResource, path);
			if (ssoFilterSingle != null)
				filters.add(ssoFilterSingle);
		}
	}

	private Filter ssoFilter(ClientResources client, String path) {
		OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(path);
		OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oauth2ClientContext);
		filter.setRestTemplate(template);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(client.getResource().getUserInfoUri(),
				client.getClient().getClientId());
		tokenServices.setRestTemplate(template);
		filter.setTokenServices(tokenServices);
		filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler() {
			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {
				this.setDefaultTargetUrl(AFTER_LOGIN_URL);
				super.onAuthenticationSuccess(request, response, authentication);
			}
		});
		return filter;
	}

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(OAuth2ClientContextFilter filter) {
		FilterRegistrationBean registration = new FilterRegistrationBean();
		registration.setFilter(filter);
		registration.setOrder(-100);
		return registration;
	}

	/*
	 * LDAP methods
	 */
	@Value("${ldap.source.baseDn:null}")
	private String ldapSourceBaseDn;

	@Value("${ldap.source.url:null}")
	private String ldapSourceUrl;

	@Autowired(required = false)
	private BaseLdapPathContextSource baseLdapPathContextSource;

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		if (baseLdapPathContextSource != null) {
			auth.ldapAuthentication().userDnPatterns("uid={0},ou=people").groupSearchBase("ou=groups")
					.contextSource(baseLdapPathContextSource).passwordCompare()
					.passwordEncoder(new LdapShaPasswordEncoder()).passwordAttribute("userPassword");
		} else {
			super.configure(auth);
		}
	}

	@Bean(name = "ldap")
	@ConditionalOnProperty(name = "ldap.source.url")
	@ConditionalOnExpression("'${ldap.source.url}' != ''")
	public DefaultSpringSecurityContextSource contextSource() {
		return new DefaultSpringSecurityContextSource(Arrays.asList(ldapSourceUrl), ldapSourceBaseDn);
	}

}
