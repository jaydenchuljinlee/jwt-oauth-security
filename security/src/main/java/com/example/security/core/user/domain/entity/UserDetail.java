package com.example.security.core.user.domain.entity;

import com.example.security.comn.entity.BaseEntity;
import com.example.security.comn.validation.user.checker.BirthDateFormatChecker;
import com.example.security.comn.validation.user.checker.EmailFormatChecker;
import com.example.security.comn.validation.user.checker.PhoneNumberFormatChecker;
import com.example.security.comn.validation.user.checker.UserNameFormatChecker;
import com.example.security.core.user.domain.exceptions.UserDomainValueException;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.Hibernate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

@Entity @Getter
@Table(name = "user_detail")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserDetail extends BaseEntity implements UserDetails {
    @Column(name = "email")
    private String email;

    @Column(name ="encoded_password")
    private String encodedPassword;

    @Column(name ="user_status")
    @Enumerated(EnumType.STRING)
    private UserStatus userStatus;

    @Column(name ="name")
    private String name;

    @Column(name ="birth_date")
    private String birthDate;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name ="gender")
    @Enumerated(EnumType.STRING)
    private Gender gender;

    @Embedded
    private Address address;

    @Column(name ="login_fail_count")
    private int loginFailCount;

    private static final int FAIL_INIT_CNT = 0;

    @Builder
    private UserDetail(String email, String encodedPassword, String userName, String phoneNumber, Gender gender) {
        this.validateAndSetEmail(email);
        this.validateAndSetEncodedPassword(encodedPassword);
        this.validateAndSetName(userName);
        this.validateAndSetPhoneNumber(phoneNumber);

        this.gender = gender;

        this.userStatus = UserStatus.NORMAL;
        this.loginFailCount = FAIL_INIT_CNT;
    }

    private void validateAndSetEmail(String email) {
        if (!EmailFormatChecker.check(email)) {
            throw new UserDomainValueException("User.email", email);
        }

        this.email = email;
    }

    private void validateAndSetEncodedPassword(String encodedPassword) {
        if (StringUtils.isBlank(encodedPassword)) {
            throw new UserDomainValueException("User.encodedPassword", email);
        }

        this.encodedPassword = encodedPassword;
    }

    private void validateAndSetName(String name) {
        if (!UserNameFormatChecker.check(name)) {
            throw new UserDomainValueException("User.userName", name);
        }

        this.name = name;
    }

    private void validateAndSetPhoneNumber(String phoneNumber) {
        if (!PhoneNumberFormatChecker.check(phoneNumber)) {
            throw new UserDomainValueException("User.phoneNumber", phoneNumber);
        }

        this.phoneNumber = phoneNumber;
    }

    private void validateAndSetBirthDate(String birthDate) {
        if (!BirthDateFormatChecker.check(birthDate)) {
            throw new UserDomainValueException("User.birthDate", birthDate);
        }

        this.birthDate = birthDate;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> result = new ArrayList<>();

        switch (this.userStatus) {
            case NORMAL:
                result.add(new SimpleGrantedAuthority("ROLE_MEMBER"));
                break;
            case ASK:
                result.add(new SimpleGrantedAuthority("ROLE_ASK"));
                break;
            default:
                result.add(new SimpleGrantedAuthority("ROLE_DROPOUT"));
                break;
        }

        return result;
    }

    @Override
    public String getPassword() {
        return this.getEncodedPassword();
    }

    @Override
    public String getUsername() {
        return this.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || Hibernate.getClass(this) != Hibernate.getClass(o)) return false;
        UserDetail that = (UserDetail) o;
        return id != null && Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
