package com.example.security.comn.validation.user.checker;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EnumFormatChecker {
    public static boolean check(Class<? extends Enum> enumClass, String enumName) {
        if (enumClass == null) {
            return false;
        }

        Enum[] enums = enumClass.getEnumConstants();

        for (Enum enum_ : enums) {
            if (enum_.name().equals(enumName)) {
                return true;
            }
        }

        return false;
    }
}
