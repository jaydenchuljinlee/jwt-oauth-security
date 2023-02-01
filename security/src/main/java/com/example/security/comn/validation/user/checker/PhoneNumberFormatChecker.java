package com.example.security.comn.validation.user.checker;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;

import java.util.regex.Pattern;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PhoneNumberFormatChecker {
    private static final String PHONE_NUMBER_REGEX = "^01([0|1|6|7|8|9])([0-9]{7,8})$";
    private static final Pattern PHONE_NUMBER_PATTERN = Pattern.compile(PHONE_NUMBER_REGEX);

    public static boolean check(String mayPhoneNumber) {
        if (StringUtils.isBlank(mayPhoneNumber)) {
            return false;
        }

        return PHONE_NUMBER_PATTERN.matcher(mayPhoneNumber).matches();
    }
}
