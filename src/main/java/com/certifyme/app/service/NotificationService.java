package com.certifyme.app.service;

import com.certifyme.app.dto.NotificationResponseDTO;
import com.certifyme.app.dto.PagedResponseDTO;
import com.certifyme.app.exception.ResourceNotFoundException;
import com.certifyme.app.mapper.NotificationMapper;
import com.certifyme.app.model.Certification;
import com.certifyme.app.model.Notification;
import com.certifyme.app.model.User;
import com.certifyme.app.repository.NotificationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class NotificationService {

    private final NotificationRepository notificationRepository;
    private final NotificationMapper mapper;

    public NotificationService(NotificationRepository notificationRepository, NotificationMapper mapper) {
        this.notificationRepository = notificationRepository;
        this.mapper = mapper;
    }

    public void createNotification(User user, Certification cert, String title, String message, String type) {
        Notification notification = Notification.builder()
                .user(user)
                .certification(cert)
                .title(title)
                .message(message)
                .type(type)
                .isRead(false)
                .build();
        notificationRepository.save(notification);
    }

    public PagedResponseDTO<NotificationResponseDTO> getUserNotifications(Long userId, Pageable pageable) {
        Page<Notification> page = notificationRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);
        List<NotificationResponseDTO> dtos = mapper.toResponseDTOList(page.getContent());
        return new PagedResponseDTO<>(dtos, page.getNumber(), page.getSize(), page.getTotalElements(), page.getTotalPages(), page.isLast());
    }

    public long getUnreadCount(Long userId) {
        return notificationRepository.countByUserIdAndIsReadFalse(userId);
    }

    public void markAsRead(Long id) {
        Notification no = notificationRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Notification not found"));
        no.setRead(true);
        no.setReadAt(LocalDateTime.now());
        notificationRepository.save(no);
    }

    public void markAllAsRead(Long userId) {
        List<Notification> unread = notificationRepository.findByUserIdAndIsReadFalse(userId);
        LocalDateTime now = LocalDateTime.now();
        unread.forEach(n -> {
            n.setRead(true);
            n.setReadAt(now);
        });
        notificationRepository.saveAll(unread);
    }

    public void deleteNotification(Long id) {
        notificationRepository.deleteById(id);
    }
}
