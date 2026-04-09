package com.certifyme.app.model;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter(autoApply = true)
public class RenewalStatusConverter implements AttributeConverter<RenewalStatus, String> {

    @Override
    public String convertToDatabaseColumn(RenewalStatus attribute) {
        if (attribute == null) {
            return RenewalStatus.NONE.name();
        }
        return attribute.name(); // Store uppercase in DB by default for new records
    }

    @Override
    public RenewalStatus convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.trim().isEmpty()) {
            return RenewalStatus.NONE;
        }
        
        for (RenewalStatus status : RenewalStatus.values()) {
            if (status.name().equalsIgnoreCase(dbData) || 
                status.name().replace("_", " ").equalsIgnoreCase(dbData)) {
                return status;
            }
        }
        
        // Return NONE if unmatched, or handle specific legacy strings
        return RenewalStatus.NONE;
    }
}
