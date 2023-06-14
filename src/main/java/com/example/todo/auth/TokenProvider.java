package com.example.todo.auth;

import com.example.todo.userapi.entity.Role;
import com.example.todo.userapi.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
@Slf4j
//역할 : 토큰을 발급하고, 서명위조를 검사하는 객체
public class TokenProvider {

    // 서명에 사용할 값(512비트 이상의 랜덤 문자열로 만들어야 함. 보안 때문에)

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    //토큰 생성 메서드
    /**
     * Json Web Token을 생성하는 메서드
     * @param userEntity - 토큰의 내용(클레임)에 포함될 유저정보
     * @return  - 생성된 json을 암호화한 토큰값
     * */
    public String createToken(User userEntity){

        //토큰 만료시간 생성
        Date expiry = Date.from(
            Instant.now().plus(1, ChronoUnit.DAYS)
        );

        //토큰 생성
        /*
            { //밑의 내용들을 클레임이라고 부름
                "iss" : "발급자 정보(회사 정보같은거 들어감)",
                "exp" : "만료시간"
                "iat" : "발급 시간"
                "email" : "로그인한 사람 이메일",
                "role" : "Premium"
                ==서명
            }
        * */

        //추가 클레임 정의
        Map<String , Object> claims = new HashMap<>();
        claims.put("email",userEntity.getEmail());
        claims.put("role",userEntity.getRole());

        return Jwts.builder()
                //token header에 들어갈 서명
                .signWith(//한번 더 암호화
                        Keys.hmacShaKeyFor(SECRET_KEY.getBytes())
                        , SignatureAlgorithm.HS512
                )
                //token payload에 들어갈 클레임 설정
                .setIssuer("아이콘") //iss : 발급자 정보
                .setIssuedAt(new Date()) //iat : 발급 시간
                .setExpiration(expiry) //exp : 만료시간
                .setSubject(userEntity.getId()) //sub : 토큰을 식별할 수 있는 주요데이터. 토큰은 보통 로그인할 때 생성함
                .setClaims(claims)
                .compact();
    }

    /**
     * 클라이언트가 전송한 토큰을 디코딩하여 토큰의 위조여부를 확인
     * 토큰을 json으로 파싱해서 클레임(토큰정보)를 리턴
     * @param token
     * @return - 토큰 안에있는 인증된 유저정보를 반환
     */
    public TokenUserInfo validateAndGetTokenUserInfo(String token) {

        Claims claims = Jwts.parserBuilder()
                // 토큰 발급자의 발급 당시의 서명을 넣어줌
                .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()))
                // 서명 위조 검사: 위조된경우 예외가 발생합니다.
                // 위조가 되지 않은 경우 페이로드를 리턴
                .build()
                .parseClaimsJws(token)
                .getBody();

        log.info("claims: {}", claims);

        return TokenUserInfo.builder()
                .userId(claims.getSubject())
                .email(claims.get("email", String.class))
                .role(Role.valueOf(claims.get("role", String.class)))
                .build();
    }


}
