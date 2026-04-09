package com.certifyme.app.controller;

import com.certifyme.app.dto.NotificationResponseDTO;
import com.certifyme.app.dto.PagedResponseDTO;
import com.certifyme.app.model.User;
import com.certifyme.app.service.NotificationService;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/student")
public class StudentNotificationController {

    private final NotificationService notificationService;

    public StudentNotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    @GetMapping("/notifications")
    public ResponseEntity<PagedResponseDTO<NotificationResponseDTO>> getStudentNotifications(
            @AuthenticationPrincipal User user,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        // Optimized: extracts userId from JWT via @AuthenticationPrincipal
        return ResponseEntity.ok(notificationService.getUserNotifications(user.getId(), PageRequest.of(page, size)));
    }

    @GetMapping("/notifications/unread-count")
    public ResponseEntity<Long> getUnreadCount(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(notificationService.getUnreadCount(user.getId()));
    }
}
