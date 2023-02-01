package com.example.security.core.user.domain.entity;

import javax.persistence.Column;
import javax.persistence.Embeddable;

@Embeddable
public class Address {
    @Column(name ="address1")
    private String address1;
    @Column(name ="address2")
    private String address2;
    @Column(name ="zip_code")
    private String zipCode;
}
