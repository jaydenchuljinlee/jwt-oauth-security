package com.example.security.comn.validation.checker;

import com.example.security.comn.validation.user.checker.PhoneNumberFormatChecker;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("PhoneNumberFormatChecker 클래스")
public class PhoneNumberFormatCheckerTest {
    @DisplayName("check 메서드는")
    @Nested
    class check {
        @DisplayName("01xxxxxxxxx 혹은 01xxxxxxxx 포맷인지 확인한다.")
        @Test
        void returnGivenValueIsPasswordFormat() {
            // 01x~ 뒤의 길이가 8이다.
            Assertions.assertThat(PhoneNumberFormatChecker.check("01012341234")).isTrue();
            // 01x~ 뒤의 길이가 7이다.
            Assertions.assertThat(PhoneNumberFormatChecker.check("0101231234")).isTrue();

        }

        @DisplayName("prefix가 01로 시작하지 않을 경우 false를 리턴한다.")
        @Test
        void returnFalseValueIfPrefixIsInvalid() {
            // 01~ 로 시작하지 않는다
            Assertions.assertThat(PhoneNumberFormatChecker.check("1231234123")).isFalse();
        }

        @DisplayName("01x ~ 뒤에 숫자의 길이가 7미만이거나 8 초과일 경우 false를 리턴한다.")
        @Test
        void returnFalseGivenValueIfLengthIsInvalid() {
            // 01x ~ 뒤에 숫자의 길이가 7미만이거나 8 초과
            Assertions.assertThat(PhoneNumberFormatChecker.check("010123412")).isFalse();
            Assertions.assertThat(PhoneNumberFormatChecker.check("010123412345")).isFalse();
        }

        @DisplayName("문자가 들어갈 경우 false를 리턴한다.")
        @Test
        void returnFalseValueIfContainsCharacter() {
            // 문자가 들어간다
            Assertions.assertThat(PhoneNumberFormatChecker.check("01a1231234")).isFalse();
        }
    }
}
