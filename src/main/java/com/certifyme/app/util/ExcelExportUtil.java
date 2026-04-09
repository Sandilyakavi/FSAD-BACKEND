package com.certifyme.app.util;

import com.certifyme.app.dto.CertificationResponseDTO;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public class ExcelExportUtil {

    public static ByteArrayInputStream generateCertificationReport(List<CertificationResponseDTO> certifications) {
        try (Workbook workbook = new XSSFWorkbook(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            Sheet sheet = workbook.createSheet("Certifications");

            // Header Style
            CellStyle headerStyle = workbook.createCellStyle();
            headerStyle.setFillForegroundColor(IndexedColors.LIGHT_BLUE.getIndex());
            headerStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
            Font headerFont = workbook.createFont();
            headerFont.setColor(IndexedColors.WHITE.getIndex());
            headerFont.setBold(true);
            headerStyle.setFont(headerFont);

            // Row 0: Header
            Row headerRow = sheet.createRow(0);
            String[] columns = {"Title", "Issuer", "Issue Date", "Expiry Date", "Status", "Renewal Status", "Credential ID"};
            
            for (int i = 0; i < columns.length; i++) {
                Cell cell = headerRow.createCell(i);
                cell.setCellValue(columns[i]);
                cell.setCellStyle(headerStyle);
            }

            // Data rows
            int rowIdx = 1;
            for (CertificationResponseDTO cert : certifications) {
                Row row = sheet.createRow(rowIdx++);
                row.createCell(0).setCellValue(cert.getTitle() != null ? cert.getTitle() : "");
                row.createCell(1).setCellValue(cert.getIssuer() != null ? cert.getIssuer() : "");
                row.createCell(2).setCellValue(cert.getFormattedIssueDate() != null ? cert.getFormattedIssueDate() : "");
                row.createCell(3).setCellValue(cert.getFormattedExpiryDate() != null ? cert.getFormattedExpiryDate() : "");
                
                String status = cert.getCertificationStatus() != null ? cert.getCertificationStatus().name() : "";
                row.createCell(4).setCellValue(status);
                
                String rStatus = cert.getRenewalStatus() != null ? cert.getRenewalStatus().name() : "";
                row.createCell(5).setCellValue(rStatus);
                
                row.createCell(6).setCellValue(cert.getCredentialId() != null ? cert.getCredentialId() : "");
            }

            // Auto-size columns
            for (int i = 0; i < columns.length; i++) {
                sheet.autoSizeColumn(i);
            }

            workbook.write(out);
            return new ByteArrayInputStream(out.toByteArray());
        } catch (IOException e) {
            throw new RuntimeException("Failed to generate Excel file", e);
        }
    }
}
