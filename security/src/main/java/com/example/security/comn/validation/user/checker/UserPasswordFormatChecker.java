package com.example.security.comn.validation.user.checker;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class UserPasswordFormatChecker {
    private static final int PASSWORD_MIN_LENGTH = 10;
    private static final String SPECIAL_CHARACTERS = "/*!@#$%^&*()\\\"{}_[]|\\?/<>,.";

    public static boolean check(String mayPassword) {
        if (StringUtils.isBlank(mayPassword)) {
            return false;
        }

        if (!isValidLength(mayPassword)) {
            return false;
        }

        if (!containsAllRequiredCharacters(mayPassword)) {
            return false;
        }

        if (containsUnsupportedCharacter(mayPassword)) {
            return false;
        }

        return true;
    }

    public static boolean isValidLength(String mayPassword) {
        return PASSWORD_MIN_LENGTH <= mayPassword.length();
    }

    public static boolean containsAllRequiredCharacters(String mayPassword) {
        boolean alphabetUpper = false;
        boolean alphabetLower = false;
        boolean number = false;
        boolean specialCharacter = false;

        for (char c : mayPassword.toCharArray()) {
            alphabetUpper = alphabetUpper || Character.isUpperCase(c);
            alphabetLower = alphabetLower || Character.isLowerCase(c);
            number = number || Character.isDigit(c);
            specialCharacter = specialCharacter || isSpecialCharacter(c);

            if (alphabetUpper && alphabetLower && number && specialCharacter) {
                return true;
            }
        }

        return false;

    }

    public static boolean containsUnsupportedCharacter(String mayPassword) {
        for (char c: mayPassword.toCharArray()) {
            if (!isSupportedCharacter(c)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isSupportedCharacter(char c) {
        return Character.isUpperCase(c) ||
                Character.isLowerCase(c) ||
                Character.isDigit(c) ||
                isSpecialCharacter(c);
    }

    private static boolean isSpecialCharacter(char c) {
        return 0 <= SPECIAL_CHARACTERS.indexOf(c);
    }
}
