package com.certifyme.app.util;

import com.certifyme.app.model.CertificationStatus;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

public class DateUtil {
    
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("dd-MM-yyyy");
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm");

    public static String formatDate(LocalDateTime dateTime) {
        if (dateTime == null) return null;
        return dateTime.format(DATE_FORMATTER);
    }

    public static String formatDateTime(LocalDateTime dateTime) {
        if (dateTime == null) return null;
        return dateTime.format(DATE_TIME_FORMATTER);
    }

    public static Long daysUntilExpiry(LocalDateTime expiryDate) {
        if (expiryDate == null) return null;
        return ChronoUnit.DAYS.between(LocalDateTime.now(), expiryDate);
    }

    public static CertificationStatus computeCertificationStatus(LocalDateTime expiryDate) {
        if (expiryDate == null) return CertificationStatus.ACTIVE;

        Long daysLeft = daysUntilExpiry(expiryDate);
        if (daysLeft < 0) {
            return CertificationStatus.EXPIRED;
        } else if (daysLeft <= 30) {
            return CertificationStatus.EXPIRING_SOON;
        } else {
            return CertificationStatus.ACTIVE;
        }
    }
}
