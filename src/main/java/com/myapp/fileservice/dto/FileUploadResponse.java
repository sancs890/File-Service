package com.myapp.fileservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FileUploadResponse {
    private Long fileId;
    private String fileName;
    private String downloadURL;
    private String fileType;
    private long fileSize;
}
