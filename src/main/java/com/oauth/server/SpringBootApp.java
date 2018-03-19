package com.oauth.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportResource;

import com.oauth.server.config.AppConfig;


/**
*
* @author  Hassan.khani
* @version 1.1.20170429
* @change 
* @target
* 
*/


@SpringBootApplication(scanBasePackages={"com.oauth"})
@Import({ AppConfig.class})
@ImportResource("classpath:spring-security.xml")
public class SpringBootApp extends SpringBootServletInitializer {
	
	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(SpringBootApp.class);
		
	}

	public static void main(String[] args) throws Exception {
		SpringApplication.run(SpringBootApp.class, args);
	}

}