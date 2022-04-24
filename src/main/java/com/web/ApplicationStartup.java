package com.web;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

/**
 * spring-boot startup
 *
 */
@SpringBootApplication
public class ApplicationStartup
{
    public static void main(String[] args) {
        SpringApplication.run(ApplicationStartup.class, args);
    }


    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }
}