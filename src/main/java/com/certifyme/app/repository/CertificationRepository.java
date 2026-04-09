package com.certifyme.app.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.certifyme.app.model.Certification;
import com.certifyme.app.model.RenewalStatus;

import java.time.LocalDateTime;
import java.util.List;

public interface CertificationRepository extends JpaRepository<Certification, Long> {
    
    @Query("SELECT c FROM Certification c JOIN FETCH c.user")
    List<Certification> findAllWithUser();
	
    Page<Certification> findByUserId(Long userId, Pageable pageable);
    List<Certification> findByUserId(Long userId);
    
    @Query("SELECT c FROM Certification c WHERE c.expiryDate BETWEEN :now AND :threshold")
    List<Certification> findExpiringSoon(@Param("now") LocalDateTime now, @Param("threshold") LocalDateTime threshold);
    
    @Query("SELECT c FROM Certification c WHERE c.expiryDate < :now")
    List<Certification> findExpired(@Param("now") LocalDateTime now);
    
    List<Certification> findByRenewalStatus(RenewalStatus status);
    
    @Query("SELECT c FROM Certification c WHERE c.expiryDate BETWEEN :now AND :threshold AND (c.lastReminderSent IS NULL OR c.lastReminderSent < :today)")
    List<Certification> findNeedingReminder(@Param("now") LocalDateTime now, @Param("threshold") LocalDateTime threshold, @Param("today") LocalDateTime today);
    
    long countByUserId(Long userId);
    
    @Query("SELECT COUNT(c) FROM Certification c WHERE c.user.id = :uid AND c.expiryDate < :now")
    long countExpiredByUserId(@Param("uid") Long uid, @Param("now") LocalDateTime now);
}