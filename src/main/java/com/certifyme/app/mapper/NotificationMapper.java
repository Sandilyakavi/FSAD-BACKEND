package com.certifyme.app.mapper;

import com.certifyme.app.dto.NotificationResponseDTO;
import com.certifyme.app.model.Notification;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class NotificationMapper {

    public NotificationResponseDTO toResponseDTO(Notification notification) {
        NotificationResponseDTO dto = new NotificationResponseDTO();
        dto.setId(notification.getId());
        dto.setTitle(notification.getTitle());
        dto.setMessage(notification.getMessage());
        dto.setType(notification.getType());
        dto.setRead(notification.isRead());
        dto.setCreatedAt(notification.getCreatedAt());
        dto.setReadAt(notification.getReadAt());
        
        if (notification.getCertification() != null) {
            dto.setCertificationId(notification.getCertification().getId());
            dto.setCertificationTitle(notification.getCertification().getTitle());
        }
        return dto;
    }

    public List<NotificationResponseDTO> toResponseDTOList(List<Notification> notifications) {
        return notifications.stream().map(this::toResponseDTO).collect(Collectors.toList());
    }
}
