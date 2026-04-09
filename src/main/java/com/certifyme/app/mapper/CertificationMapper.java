package com.certifyme.app.mapper;

import com.certifyme.app.dto.CertificationRequestDTO;
import com.certifyme.app.dto.CertificationResponseDTO;
import com.certifyme.app.model.Certification;
import com.certifyme.app.model.CertificationStatus;
import com.certifyme.app.model.RenewalStatus;
import com.certifyme.app.util.DateUtil;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class CertificationMapper {

    private final UserMapper userMapper;

    public CertificationMapper(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public Certification toEntity(CertificationRequestDTO dto) {
        return Certification.builder()
                .title(dto.getTitle())
                .issuer(dto.getIssuer())
                .credentialId(dto.getCredentialId())
                .url(dto.getUrl())
                .remarks(dto.getRemarks())
                .issueDate(dto.getIssueDate())
                .expiryDate(dto.getExpiryDate())
                .renewalStatus(RenewalStatus.NONE)
                .build();
    }

    public CertificationResponseDTO toResponseDTO(Certification cert) {
        CertificationResponseDTO dto = new CertificationResponseDTO();
        dto.setId(cert.getId());
        dto.setTitle(cert.getTitle());
        dto.setIssuer(cert.getIssuer());
        dto.setCredentialId(cert.getCredentialId());
        dto.setUrl(cert.getUrl());
        dto.setRemarks(cert.getRemarks());
        dto.setRenewalStatus(cert.getRenewalStatus());
        dto.setIssueDate(cert.getIssueDate());
        dto.setExpiryDate(cert.getExpiryDate());
        dto.setRequestedOn(cert.getRequestedOn());
        dto.setApprovedOn(cert.getApprovedOn());
        dto.setRejectedOn(cert.getRejectedOn());
        dto.setLastReminderSent(cert.getLastReminderSent());

        if (cert.getUser() != null) {
            dto.setUser(userMapper.toResponseDTO(cert.getUser()));
        }

        // Computed logic
        CertificationStatus status = DateUtil.computeCertificationStatus(cert.getExpiryDate());
        dto.setCertificationStatus(status);
        
        Long daysUntilExpiry = DateUtil.daysUntilExpiry(cert.getExpiryDate());
        dto.setDaysUntilExpiry(daysUntilExpiry);
        
        dto.setFormattedIssueDate(DateUtil.formatDate(cert.getIssueDate()));
        dto.setFormattedExpiryDate(DateUtil.formatDate(cert.getExpiryDate()));

        // Eligibility for renewal
        boolean isExpiredOrExpiring = status == CertificationStatus.EXPIRED || status == CertificationStatus.EXPIRING_SOON;
        boolean hasNoPendingRenewal = cert.getRenewalStatus() == null || cert.getRenewalStatus() == RenewalStatus.NONE || cert.getRenewalStatus() == RenewalStatus.REJECTED;
        dto.setRenewalEligible(isExpiredOrExpiring && hasNoPendingRenewal);

        return dto;
    }

    public List<CertificationResponseDTO> toResponseDTOList(List<Certification> certs) {
        return certs.stream().map(this::toResponseDTO).collect(Collectors.toList());
    }
}
