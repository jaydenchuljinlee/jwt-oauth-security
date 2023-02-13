package com.example.security.comn.validation.checker;

import com.example.security.comn.validation.user.checker.UserPasswordFormatChecker;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("UserPsswordFormatChecker 클래스")
public class UserPasswordFormatCheckerTest {
    @DisplayName("check 메서드는")
    @Nested
    class checker {
        @DisplayName("10자 이상이고 영문 대문자, 영문 소문자, 특수 문자, 숫자 각 1개 이상씩 포함되었는지 확인한다")
        @Test
        void returnsGivenValueIsPasswordFormat() {
            Assertions.assertThat(UserPasswordFormatChecker.check("AAAaaa!!11")).isTrue();
            // 대문자 1개
            assertThat(UserPasswordFormatChecker.check("Aaaaaa!!11")).isTrue();
            // 소문자 1개
            assertThat(UserPasswordFormatChecker.check("AAAAAa!!11")).isTrue();
            // 특수문자 1개
            assertThat(UserPasswordFormatChecker.check("AAAaaa!111")).isTrue();
            // 숫자 1개
            assertThat(UserPasswordFormatChecker.check("AAAaaa!!!1")).isTrue();
        }

        @DisplayName("10자 미만인 경우 false를 리턴한다")
        @Test
        void returnsFalseIfLengthIsLessThan10() {
            // 9자
            Assertions.assertThat(UserPasswordFormatChecker.check("AAAaaa!!1")).isFalse();
        }

        @DisplayName("영문 대문자 미포함인 경우 false를 리턴한다")
        @Test
        void returnsFalseIfNotContainsUpperCase() {
            Assertions.assertThat(UserPasswordFormatChecker.check("bbbaaa!!11")).isFalse();

        }

        @DisplayName("영문 소문자 미포함인 경우 false를 리턴한다")
        @Test
        void returnsFalseIfNotContainsLowerCase() {
            Assertions.assertThat(UserPasswordFormatChecker.check("AAAAAA!!11")).isFalse();

        }

        @DisplayName("특수문자 미포함인 경우 false를 리턴한다")
        @Test
        void returnsFalseIfNotContainsSpecialCharacter() {
            Assertions.assertThat(UserPasswordFormatChecker.check("AAAaaa1111")).isFalse();

        }

        @DisplayName("숫자 미포함인 경우 false를 리턴한다")
        @Test
        void returnsFalseIfNotContainsNumber() {
            Assertions.assertThat(UserPasswordFormatChecker.check("AAAaaa!!!!")).isFalse();

        }

        @DisplayName("영문, 특수 문자, 숫자 외 문자 포함인 경우 false를 리턴한다")
        @Test
        void returnsFalseIfContainsUnsupportedCharacter() {
            // 한글
            Assertions.assertThat(UserPasswordFormatChecker.check("ㅁAAaaa11!!")).isFalse();
            // 공백
            Assertions.assertThat(UserPasswordFormatChecker.check(" AAaaa11!!")).isFalse();
        }
    }
}
