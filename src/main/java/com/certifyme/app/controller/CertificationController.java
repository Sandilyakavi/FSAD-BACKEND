package com.certifyme.app.controller;

import com.certifyme.app.dto.*;
import com.certifyme.app.service.CertificationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.InputStreamResource;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.util.List;

@RestController
@RequestMapping("/api/certifications")
public class CertificationController {

    private final CertificationService service;

    public CertificationController(CertificationService service) {
        this.service = service;
    }

    @PostMapping("/user/{userId}")
    public ResponseEntity<CertificationResponseDTO> create(@PathVariable Long userId, @Valid @RequestBody CertificationRequestDTO request) {
        return ResponseEntity.ok(service.saveCertification(userId, request));
    }

    @GetMapping("/user/{userId}/paged")
    public ResponseEntity<PagedResponseDTO<CertificationResponseDTO>> getByUserPaged(
            @PathVariable Long userId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(service.getByUser(userId, PageRequest.of(page, size)));
    }
    
    // Kept for backward compatibility with frontend
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<CertificationResponseDTO>> getByUser(@PathVariable Long userId) {
        return ResponseEntity.ok(service.getByUser(userId));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PagedResponseDTO<CertificationResponseDTO>> getAll(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(service.getAll(PageRequest.of(page, size)));
    }
    
    // Kept for backward compatibility
    @GetMapping("/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<CertificationResponseDTO>> getAllCertifications() {
        return ResponseEntity.ok(service.getAllForAdmin());
    }

    @PutMapping("/{id}")
    public ResponseEntity<CertificationResponseDTO> update(@PathVariable Long id, @Valid @RequestBody CertificationRequestDTO request) {
        return ResponseEntity.ok(service.updateCertification(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.deleteCertification(id);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}/renewal")
    public ResponseEntity<CertificationResponseDTO> updateRenewalStatus(
            @PathVariable Long id,
            @RequestParam String status) {
        return ResponseEntity.ok(service.updateRenewalStatus(id, status));
    }

    @PutMapping("/{id}/remind")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<CertificationResponseDTO> sendReminder(@PathVariable Long id) {
        return ResponseEntity.ok(service.sendReminder(id));
    }

    @GetMapping("/expiring")
    public ResponseEntity<List<CertificationResponseDTO>> getExpiringSoon() {
        return ResponseEntity.ok(service.getExpiringSoon());
    }

    @GetMapping("/expired")
    public ResponseEntity<List<CertificationResponseDTO>> getExpired() {
        return ResponseEntity.ok(service.getExpired());
    }
    
    @GetMapping("/renewals")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<CertificationResponseDTO>> getPendingRenewals() {
        return ResponseEntity.ok(service.getPendingRenewals());
    }

    @GetMapping("/stats/{userId}")
    public ResponseEntity<DashboardStatsDTO> getDashboardStats(@PathVariable Long userId) {
        return ResponseEntity.ok(service.getDashboardStats(userId));
    }

    @GetMapping("/export")
    public ResponseEntity<InputStreamResource> exportAllToExcel() {
        ByteArrayInputStream in = service.exportToExcel(null);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=certifications.xlsx");

        return ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .body(new InputStreamResource(in));
    }

    @GetMapping("/export/{userId}")
    public ResponseEntity<InputStreamResource> exportUserToExcel(@PathVariable Long userId) {
        ByteArrayInputStream in = service.exportToExcel(userId);
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=certifications_user_" + userId + ".xlsx");

        return ResponseEntity.ok()
                .headers(headers)
                .contentType(MediaType.parseMediaType("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .body(new InputStreamResource(in));
    }
}
