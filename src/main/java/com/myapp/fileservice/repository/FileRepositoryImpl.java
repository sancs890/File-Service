package com.myapp.fileservice.repository;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.myapp.fileservice.models.File;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.TypedQuery;

@Component
public class FileRepositoryImpl {

    @PersistenceContext
    private EntityManager entityManager;

    public List<File> getFilesAndFolderForUser(Long userId) {
        String hqlQuery = "select file from File file where file.userId = :userId and file.folderId = null";
        TypedQuery<File> typedQuery = entityManager.createQuery(hqlQuery, File.class);
        typedQuery.setParameter("userId", userId);
        return typedQuery.getResultList();
    }
    
    
    public List<File> getFilesByUserIdAndFolderId(Long userId, Long folderId) {
        String hqlQuery = "select file from File file where file.userId = :userId and file.folderId = :folderId";
        TypedQuery<File> typedQuery = entityManager.createQuery(hqlQuery, File.class);
        typedQuery.setParameter("userId", userId);
        typedQuery.setParameter("folderId", folderId);
        return typedQuery.getResultList();
    }

}
