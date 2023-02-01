package com.example.security.comn.validation.user.validator;

import com.example.security.comn.validation.user.annotation.PhoneNumberFormat;
import com.example.security.comn.validation.user.checker.PhoneNumberFormatChecker;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class PhoneNumberValidator implements ConstraintValidator<PhoneNumberFormat, String> {
    private boolean nullable = false;


    @Override
    public void initialize(PhoneNumberFormat constraintAnnotation) {
        this.nullable = constraintAnnotation.nullable();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (nullable) {
            return true;
        }

        return PhoneNumberFormatChecker.check(value);
    }
}
