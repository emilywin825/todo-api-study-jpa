package com.example.todo.userapi.api;

import com.example.todo.auth.TokenUserInfo;
import com.example.todo.exception.DuplicatedEmailException;
import com.example.todo.exception.NoRegisteredArgumentsException;
import com.example.todo.userapi.dto.request.LoginRequestDTO;
import com.example.todo.userapi.dto.request.UserRequestSignUpDTO;
import com.example.todo.userapi.dto.response.LoginResponseDTO;
import com.example.todo.userapi.dto.response.UserSignUpResponseDTO;
import com.example.todo.userapi.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.util.FileCopyUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.MediaTypeNotSupportedStatusException;

import java.io.File;
import java.io.IOException;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class UserController {

    private final UserService userService;

    // 이메일 중복확인 요청 처리
    // GET: /api/auth/check?email=zzzz@xxx.com
    @GetMapping("/check")
    public ResponseEntity<?> check(String email) {
        if (email.trim().equals("")) {
            return ResponseEntity.badRequest()
                    .body("이메일이 없습니다!");
        }
        boolean resultFlag = userService.isDuplicate(email);
        log.info("{} 중복?? - {}", email, resultFlag);

        return ResponseEntity.ok().body(resultFlag);
    }

    // 회원가입 요청처리
    // POST: /api/auth
    @PostMapping
    public ResponseEntity<?> signUp(
            //JSON만 날라오면 @RequestBody UserRequestSignUpDTO dto
            //근데 JSON이랑 이미지파일 같이 날라오니까 멀티파트파일과 분리해줘야 함
            //근데 JSON이랑 멀티파트랑 구분못해서 @RequestPart이거 작성
            @Validated @RequestPart("user") UserRequestSignUpDTO dto
            //required = false 이거 작성안하면 프로필이미지 안 보내면 에러남
            , @RequestPart(value = "profileImage", required = false) MultipartFile profileImg
            , BindingResult result
    ) {
        log.info("/api/auth POST! - {}", dto);

        if (result.hasErrors()) {
            log.warn(result.toString());
            return ResponseEntity.badRequest()
                    .body(result.getFieldError());
        }

        try {
            String uploadedFilePath = null;
            if(profileImg != null) {
                log.info("attached file name: {}", profileImg.getOriginalFilename());
                uploadedFilePath = userService.uploadProfileImage(profileImg);
            }

            UserSignUpResponseDTO responseDTO = userService.create(dto, uploadedFilePath);
            return ResponseEntity.ok()
                    .body(responseDTO);

        } catch (NoRegisteredArgumentsException e) {
            log.warn("필수 가입 정보를 전달받지 못했습니다.");
            return ResponseEntity.badRequest()
                    .body(e.getMessage());
        } catch (DuplicatedEmailException e) {
            log.warn("이메일 중복입니다!");
            return ResponseEntity.badRequest()
                    .body(e.getMessage());
        } catch (Exception e) {
            log.warn("기타 예외가 발생했습니다.");
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }

    }

    // 로그인 요청 처리
    @PostMapping("/signin")
    public ResponseEntity<?> signIn(
            @Validated @RequestBody LoginRequestDTO dto
    ) {
        try {
            LoginResponseDTO responseDTO
                    = userService.authenticate(dto);

            return ResponseEntity.ok().body(responseDTO);

        } catch (Exception e) {

            e.printStackTrace();
            return ResponseEntity
                    .badRequest()
                    .body(e.getMessage());
        }
    }

    //프로필 사진 이미지 데이터를 클라에게 응답처리
    @GetMapping("/load-profile")
    public ResponseEntity<?> loadFile(
            @AuthenticationPrincipal TokenUserInfo userInfo
    ){
        log.info("api/auth/load-profile GET ! - user:{}",userInfo);

        try {
            //클라이언트가 요청한 프로필 사진을 응답해야 함
            // 1. 프로필 사진의 경로를 얻어야 함.
            String filePath= userService.findProfilePath(userInfo.getUserId());

            // 2. 얻어낸 파일 경로를 통해서 실제 파일데이터 로드하기
            File profileFile = new File(filePath);

            if(!profileFile.exists()){
                return ResponseEntity.notFound().build();
            }

            //해당 경로에 저장된 파일을 바이트배열로 직렬화해서 리턴
            byte[] fileData = FileCopyUtils.copyToByteArray(profileFile);


            //3. 응답 헤더에 컨텐츠 타입을 설정
            //우리가 응답하는 데이터가 어떤 데이터인지 알려줘야 함
            //그동안은 우리가 계속 json만 리턴하니까 응답해더(.headers())를 안써줬는데
            //이번에는 이미지파일까지 같이 하니까 설정해줘야 함
            HttpHeaders headers = new HttpHeaders();
            MediaType contentType = findExtensionAndGetMediaType(filePath); //확장자를 찾아서 미디어를 가져옴

            if (contentType == null) {
                return ResponseEntity.internalServerError()
                        .body("발견된 파일은 이미지 파일이 아닙니다.");
            }
            headers.setContentType(contentType);

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(fileData);

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError()
                    .body("파일을 찾을 수 없습니다.");
        }
    }

    private MediaType findExtensionAndGetMediaType(String filePath) {

        //파일경로에서 확장자 추출하기
        //D:/todo_upload/asdfwesdlfjweoijfal.jpg
        //.다음 글자부터 끝까지 자름
        String ext = filePath.substring(filePath.lastIndexOf(".") + 1);


        switch (ext.toUpperCase()){
            case "JPG": case "JPEG":
                return MediaType.IMAGE_JPEG;
            case "PNG":
                 return MediaType.IMAGE_PNG;
            case "GIF":
                return MediaType.IMAGE_GIF;
            default:
                return null;

        }
    }

}