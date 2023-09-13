package com.myapp.fileservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.myapp.fileservice.models.File;

import jakarta.transaction.Transactional;

import java.util.List;

public interface FileRepository extends JpaRepository<File, Long> {
    @Transactional
    public List<File> getFilesByUserIdAndFolderId(Long userId, Long folderId);

    @Transactional
    public List<File> getFilesAndFolderForUser(Long userId);

}
