# jwt-oauth-security
jwt 토큰과 oauth 로그인을 통한 spring security 구성


Argon2PasswordEncoder.encode() 사용 시, 에러
- implementation 'org.bouncycastle:bcprov-jdk15on:1.64' devpendency 추가
- 관련 이슈 https://github.com/spring-projects/spring-security/issues/8842