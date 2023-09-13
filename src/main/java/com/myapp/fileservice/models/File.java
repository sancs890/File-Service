package com.myapp.fileservice.models;

import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

@Entity
@Data
@NoArgsConstructor
@Table(name = "files")
@Getter
@Setter
public class File {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "file_name")
    private String fileName;
    @Column(name = "is_folder")
    private boolean isFolder;
    @Column(name = "file_type")
    private String fileType;
    @Lob
    private byte[] data;
    @Column(name = "created_at")
    @CreationTimestamp
    private Instant createdAt;

    @Column(name = "updated_at")
    @UpdateTimestamp
    private Instant updatedAt;
    @Column(name = "folder_id")
    private Long folderId;
    @Column(name = "user_id")
    private Long userId;

    public File(String fileName, String fileType, byte[] data, Long userId) {
        this.fileName = fileName;
        this.fileType = fileType;
        this.data = data;
        this.userId = userId;
        this.isFolder = false;
    }
}
