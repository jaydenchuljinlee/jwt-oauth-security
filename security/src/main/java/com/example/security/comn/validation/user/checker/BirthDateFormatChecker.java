package com.example.security.comn.validation.user.checker;

import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

public class BirthDateFormatChecker {
    private static final String EMAIL_REGEX = "/^\\d{4}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])$/";
    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

    public static boolean check(String mayEmail) {
        if (StringUtils.isBlank(mayEmail)) {
            return false;
        }


        return EMAIL_PATTERN.matcher(mayEmail).matches();
    }
}
