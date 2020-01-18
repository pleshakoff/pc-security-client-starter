package com.parcom.security_client;


import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@ConfigurationProperties(prefix = "parcom.security")
public class SecurityProps {

    private List<String> permitted =  new ArrayList<>();



}
