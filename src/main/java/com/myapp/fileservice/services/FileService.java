package com.myapp.fileservice.services;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import com.myapp.fileservice.models.File;
import com.myapp.fileservice.repository.FileRepository;

@Service
public class FileService {

    @Autowired
    private FileRepository fileRepository;

    public File saveFile(MultipartFile file, Long userId) throws Exception {
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());

        try {
            if (fileName.contains("..")) {
                throw new Exception("The file name is invalid" + fileName);
            }
            File fileUpload = new File(fileName, file.getContentType(), file.getBytes(), userId);
            return fileRepository.save(fileUpload);
        } catch (Exception e) {
            throw new Exception("File could not be save", e);
        }
    }

    public File saveFile(MultipartFile file, Long userId, Long folderId) throws Exception {
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());

        try {
            if (fileName.contains("..")) {
                throw new Exception("The file name is invalid" + fileName);
            }
            File fileUpload = new File(fileName, file.getContentType(), file.getBytes(), userId);
            fileUpload.setFolderId(folderId);
            return fileRepository.save(fileUpload);
        } catch (Exception e) {
            throw new Exception("File could not be save", e);
        }
    }

    public File saveFile(File file, Long userId) throws Exception {
        try {
            if (file.getFileName().contains("..")) {
                throw new Exception("The file name is invalid" + file.getFileName());
            }

            file.setUserId(userId);
            file.setFileType("text/directory");
            file.setFolder(true);
            return fileRepository.save(file);
        } catch (Exception e) {
            throw new Exception("File could not be save", e);
        }
    }

    public File downloadFile(Long fileId) throws Exception {
        return fileRepository.findById(fileId)
                .orElseThrow(() -> new Exception("A file with Id : " + fileId + " could not be found"));
    }

    public List<File> getFolderFiles(Long userId, Long folderId) throws Exception {
        return fileRepository.getFilesByUserIdAndFolderId(userId, folderId);
    }

    public List<File> getUserFiles(Long userId) throws Exception {
        return fileRepository.getFilesAndFolderForUser(userId);
    }
    
    public File updateFolder(Long fileId, File file) throws Exception {
    	File actualFile = fileRepository.findById(fileId).orElseThrow(() -> new Exception("A file with Id : " + fileId + " could not be found"));
    	actualFile.setFolderId(file.getFolderId());
    	fileRepository.saveAndFlush(actualFile);
		return actualFile;
    }
}
