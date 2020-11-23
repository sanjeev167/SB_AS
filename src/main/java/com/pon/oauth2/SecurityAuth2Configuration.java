/**
 * 
 */
package com.pon.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

/**
 * @author Sanjeev Kumar
 * @Date Dec 7, 2018
 * @Time 2:54:29 AM
 */

@Configuration
@EnableAuthorizationServer // to enable auth 2.0 authentication server
public class SecurityAuth2Configuration extends AuthorizationServerConfigurerAdapter {

	static final String CLIEN_ID = "PracticeOnNet";
	static final String CLIENT_SECRET = "secret";
	
	static final String GRANT_TYPE = "password";
	//static final String GRANT_TYPE = "authorization_code";	
	//static final String GRANT_TYPE = "implicit";
	//static final String GRANT_TYPE = "client_credentials";
	
	
	static final String REFRESH_TOKEN = "refresh_token";
	static final String SCOPE_READ = "read";
	static final String SCOPE_WRITE = "write";
	static final String TRUST = "trust";
	static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1 * 60 * 60;
	static final int REFRESH_TOKEN_VALIDITY_SECONDS = 6 * 60 * 60;

	@Autowired
	private TokenStore tokenStore;// Has already been configured in SecurityConfig.
	
	@Autowired
	JwtAccessTokenConverter jwtTokenEnhancer;// Has already been configured in SecurityConfig.

	@Autowired
	private AuthenticationManager authenticationManager;// Has already been configured in SecurityConfig

	@Autowired
	BCryptPasswordEncoder passwordEncoder;// Has already been configured in SecurityConfig

	/**
	 * This method is configured in advance for receiving a request for
	 * tokenKeyAccess using oauth/token_key and checkTokenAccess using
	 * oauth/check_token.
	 * 
	 * Remark: This is required to be configured when AS and RS both are separate.
	 **/

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		     clients.inMemory()
		        .withClient(CLIEN_ID).secret(passwordEncoder.encode(CLIENT_SECRET))
		        .resourceIds("")
				.accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS) // expire time for access token
				.refreshTokenValiditySeconds(REFRESH_TOKEN_VALIDITY_SECONDS) // expire time for refresh token
				.scopes(SCOPE_READ, SCOPE_WRITE) // scope related to resource server
				.authorizedGrantTypes(GRANT_TYPE, REFRESH_TOKEN); // grant type	password	        
		        // .authorizedGrantTypes(GRANT_TYPE).autoApprove(true); // grant type
		     
		     
		     
		     
		     
	}

	/**
	 * Here, we are configuring AuthorizationServerEndpointsConfigurer with
	 * authenticationManager so that it could check the client authentication.
	 **/
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		         endpoints
		                 .tokenStore(tokenStore)// Tell which tokenStore it will use
			             .tokenEnhancer(jwtTokenEnhancer)//Required when self signed jwt token is implemented
			                                             //Not required in case of In-MemoryTokenStore and JdbcTokenStore
			             .authenticationManager(authenticationManager);
	}
	
	
	//Following code is not a part of AS configuration. Will be used for checking proof of concept only.	

	@EventListener
	public void authSuccessEventListener(AuthenticationSuccessEvent authorizedEvent) {	
		
		// write custom code here for login success audit
		System.out.println("\nAS [Authentication Success] => Will check authentication in the following cases."
				+ " \n [1] When the client comes here for access token with a user and client credential."
				+ " \n [2] When RS comes here for token verification [auth/check_token]."
				+ " \n [3] When RS comes here for [auth/token_key] in case of jwt token.");
		
		System.out.println("\n Client or User Name : " + authorizedEvent.getAuthentication().getName());
		System.out.println(" Client or User Authorities : " + authorizedEvent.getAuthentication().getAuthorities());
		System.out.println(" Client or User Details : " + authorizedEvent.getAuthentication().getDetails());
	}

	@EventListener
	public void authFailedEventListener(AbstractAuthenticationFailureEvent oAuth2AuthenticationFailureEvent) {
		// write custom code here login failed audit.
		System.out.println("\nAS [Authentication Failure] => Will check authentication in the following cases."
				+ " \n [1] When the client comes here for access token with user and client credential."
				+ " \n [2] When RS comes here for token verification [auth/check_token]."
				+ " \n [3] When RS comes here for [auth/token_key] in case of jwt token.");
		
		System.out.println("\n Client or User Name : " + oAuth2AuthenticationFailureEvent.getAuthentication().getName());
		System.out.println(" Client or User Authorities : "+ oAuth2AuthenticationFailureEvent.getAuthentication().getAuthorities());
		System.out.println(" Client or User Details : " + oAuth2AuthenticationFailureEvent.getAuthentication().getDetails());
	}

	
}