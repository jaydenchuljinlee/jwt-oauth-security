package com.example.security.comn.response;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class BaseResponse<T> {
    private static final String SUCCESS_MESSAGE = "OK";
    @JsonProperty("success")
    private boolean success;

    @JsonProperty("message")
    private String message;

    @JsonProperty("data")
    private T data;

    private BaseResponse(boolean success, String message, T data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }

    public static <T> BaseResponse<T> success() {
        return success(null);
    }

    public static <T> BaseResponse<T> success(T data) {
        return new BaseResponse<>(true, SUCCESS_MESSAGE, data);
    }

    public static <T> BaseResponse<T> fail(String failMessage) {
        return fail(failMessage, null);
    }

    public static <T> BaseResponse<T> fail(String failMessage, T data) {
        return new BaseResponse<>(false, failMessage, data);
    }
}
