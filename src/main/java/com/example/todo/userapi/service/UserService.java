package com.example.todo.userapi.service;

import com.example.todo.auth.TokenProvider;
import com.example.todo.exception.DuplicatedEmailException;
import com.example.todo.exception.NoRegisteredArgumentsException;
import com.example.todo.userapi.dto.request.LoginRequestDTO;
import com.example.todo.userapi.dto.request.UserRequestSignUpDTO;
import com.example.todo.userapi.dto.response.LoginResponseDTO;
import com.example.todo.userapi.dto.response.UserSignUpResponseDTO;
import com.example.todo.userapi.entity.User;
import com.example.todo.userapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    private final TokenProvider tokenProvider;

    @Value("${upload.path}") //.yml에서 지정한 경로
    private String uploadRootPath;

    // 회원가입 처리
    public UserSignUpResponseDTO create(
            final UserRequestSignUpDTO dto
            ,final String uploadedFilePath)
            throws RuntimeException {

        if (dto == null) {
            throw new NoRegisteredArgumentsException("가입 정보가 없습니다.");
        }
        String email = dto.getEmail();

        if (isDuplicate(email)) {
            log.warn("이메일이 중복되었습니다. - {}", email);
            throw new DuplicatedEmailException("중복된 이메일입니다.");
        }

        // 패스워드 인코딩
        String encoded = encoder.encode(dto.getPassword());
        dto.setPassword(encoded);

        // 유저 엔터티로 변환
        User user = dto.toEntity(uploadedFilePath);

        User saved = userRepository.save(user);

        log.info("회원가입 정상 수행됨! - saved user - {}", saved);

        return new UserSignUpResponseDTO(saved);

    }

    public boolean isDuplicate(String email) {
        return userRepository.existsByEmail(email);
    }

    //회원 인증
    public LoginResponseDTO authenticate(final LoginRequestDTO dto) {
        //이메일을 통해 회원 정보 조회
        User user=userRepository.findByEmail(dto.getEmail())
                .orElseThrow(
                        ()->new RuntimeException("가입된 회원이 아닙니다!")
                );

        //패스워드 검증
        String rawPassword = dto.getPassword(); //입력 비번
        String encodedPassword=user.getPassword(); //DB에 저장된 비번
    if(!encoder.matches(rawPassword,encodedPassword)){
        throw new RuntimeException("비밀번호가 틀렸습니다.");
    }

        log.info("{}님 로그인 성공!!",user.getUserName());

        //로그인 성공 후에 클라이언트에 뭘 리턴할 것인가??
        //->JWT를 클라이언트에게 발급해줘야 함. 토큰을 만드는 객체를 따로 만듦
        String token = tokenProvider.createToken(user);

        return new LoginResponseDTO(user,token);

    }

    /**
     * 업로드된 파일을 서버에 저장하고 저장 경로를 리턴
     * @param originalFile - 업로드된 파일의 정보
     * @return 실제로 저장된 이미지의 경로
     */
    public String uploadProfileImage(MultipartFile originalFile) throws IOException {

        // 루트 디렉토리가 존재하는지 확인 후 존재하지 않으면 생성
        File rootDir = new File(uploadRootPath);
        if (!rootDir.exists()) rootDir.mkdir();

        // 파일명을 유니크하게 변경
        String uniqueFileName = UUID.randomUUID()
                + "_" + originalFile.getOriginalFilename();

        // 파일을 저장
        File uploadFile = new File(uploadRootPath + "/" + uniqueFileName);
        originalFile.transferTo(uploadFile);

        return uniqueFileName;
    }

    public String findProfilePath(String userId) {
        User user= userRepository.findById(userId)
                .orElseThrow();

        return user.getProfileImg();
    }
}