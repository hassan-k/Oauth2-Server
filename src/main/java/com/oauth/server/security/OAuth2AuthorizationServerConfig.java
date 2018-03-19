package com.oauth.server.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ResourceLoaderAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;


@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter implements ResourceLoaderAware {
	

	@Value("${RSA.key.jksstore}")
	private String keyPath;
	
	@Value("${RSA.key.password}")
	private String password;
	
	@Value("${auth.username}")
	private String client;
	
	@Value("${auth.password}")
	private String secret;
	
	@Value("${token.validity.access}")
	private int accessTokenValidity;
	
	@Value("${token.validity.refresh}")
	private int refreshTokenValidity;
	
	@Value("${auth.keyjks}")
	private String keyjks;
	
	private ResourceLoader resourceLoader;
	
	
	  
	public ResourceLoader getResourceLoader() {
		return resourceLoader;
	}

	@Override
	public void setResourceLoader(ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}

	@Autowired
    @Qualifier("authenticationManager")
    private AuthenticationManager authenticationManager;
    
    
    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer
        	.tokenKeyAccess("permitAll()")
        	.checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception { 
		clients
			.inMemory()
			.withClient(client)
				.secret(secret)
				.authorizedGrantTypes("password", "authorization_code", "refresh_token")		
				.scopes("read", "write")
				.accessTokenValiditySeconds(accessTokenValidity)
				.refreshTokenValiditySeconds(refreshTokenValidity);				
	} 

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) { 
		endpoints
			.tokenStore(tokenStore()).allowedTokenEndpointRequestMethods(HttpMethod.POST)
			.accessTokenConverter(accessTokenConverter())
			.authenticationManager(authenticationManager);
    }
	
	// JWT

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        final DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore());
        tokenServices.setSupportRefreshToken(true);
        return tokenServices;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyStoreKeyFactory keyStoreKeyFactory = 
        	      new KeyStoreKeyFactory(this.resourceLoader.getResource(this.keyPath), this.password.toCharArray());
        	    converter.setKeyPair(keyStoreKeyFactory.getKeyPair(keyjks));
        return converter;
    }
    
   @Bean
    public FilterRegistrationBean corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }

}
