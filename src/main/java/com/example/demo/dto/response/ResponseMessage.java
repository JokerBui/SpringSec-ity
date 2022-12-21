package com.example.demo.dto.response;

public class ResponseMessage {
    private String massage;
    public ResponseMessage(){

    }
    public ResponseMessage(String message){
        this.massage=message;
    }

    public String getMassage() {
        return massage;
    }

    public void setMassage(String massage) {
        this.massage = massage;
    }
}
