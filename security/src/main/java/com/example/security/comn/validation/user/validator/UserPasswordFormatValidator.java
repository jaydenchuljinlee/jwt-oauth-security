package com.example.security.comn.validation.user.validator;

import com.example.security.comn.validation.user.annotation.UserPasswordFormat;
import com.example.security.comn.validation.user.checker.UserPasswordFormatChecker;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class UserPasswordFormatValidator implements ConstraintValidator<UserPasswordFormat, String> {
    private boolean nullable = false;


    @Override
    public void initialize(UserPasswordFormat constraintAnnotation) {
        this.nullable = constraintAnnotation.nullable();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (nullable) {
            return true;
        }

        return UserPasswordFormatChecker.check(value);
    }
}
