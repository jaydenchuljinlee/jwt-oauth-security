package com.example.security.comn.validation.user.validator;

import com.example.security.comn.validation.user.annotation.EnumFormat;
import com.example.security.comn.validation.user.checker.EnumFormatChecker;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class EnumValidator implements ConstraintValidator<EnumFormat, String> {
    private boolean nullable = false;
    private Class<? extends Enum> enumClass;

    @Override
    public void initialize(EnumFormat constraintAnnotation) {
        this.nullable = constraintAnnotation.nullable();
        enumClass = constraintAnnotation.enumClass();
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (nullable) {
            return true;
        }

        return EnumFormatChecker.check(enumClass, value);
    }
}
