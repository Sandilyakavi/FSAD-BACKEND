package com.certifyme.app.model;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum RenewalStatus {
    NONE,
    PENDING,
    APPROVED,
    REJECTED;

    @com.fasterxml.jackson.annotation.JsonValue
    public String toValue() {
        return this.name();
    }

    @JsonCreator
    public static RenewalStatus fromString(String value) {
        if (value == null) return NONE;
        for (RenewalStatus status : RenewalStatus.values()) {
            if (status.name().equalsIgnoreCase(value)) {
                return status;
            }
        }
        return NONE;
    }
}
