package com.example.todo.todoapi.dto.response;

import com.example.todo.userapi.entity.User;
import lombok.*;

import java.util.List;

@Setter
@Getter
@ToString
@EqualsAndHashCode
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TodoListResponseDTO {

    private String error; // 에러발생시 에러메시지를 담을 필드
    private List<TodoDetailResponseDTO> todos;
}