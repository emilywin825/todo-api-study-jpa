package com.example.todo.userapi.repository;

import com.example.todo.userapi.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,String> {

    //쿼리 메서드 생성

    //이메일로 회원정보 조회
    Optional<User> findByEmail(String email);

    //이메일 중복체크
//  existsBy로 하면 @Query("select count(*) from User u where u.email=:email") 이게 자동으로 나감
    boolean existsByEmail(String email);
    
}

