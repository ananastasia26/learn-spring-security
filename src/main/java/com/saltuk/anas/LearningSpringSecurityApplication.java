package com.saltuk.anas;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class LearningSpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(LearningSpringSecurityApplication.class, args);
	}

}
