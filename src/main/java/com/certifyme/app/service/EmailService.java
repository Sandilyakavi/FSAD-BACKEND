package com.certifyme.app.service;

import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void sendOtpEmail(String toEmail, String otp) {
        System.out.println("EMAIL_USER: " + System.getenv("EMAIL_USER"));
        System.out.println("EMAIL_PASS: " + (System.getenv("EMAIL_PASS") != null ? "LOADED" : "NULL"));
        System.out.println("Sending OTP to: " + toEmail);
        
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);

            helper.setTo(toEmail);
            helper.setSubject("Admin Login - Verification Code");

            String content = "<h3>Hello Admin,</h3>"
                    + "<p>You are attempting to log in to the CertifyMe Dashboard.</p>"
                    + "<p>Your 6-digit verification code is: <b style=\"color: #6366f1; font-size: 20px;\">" + otp + "</b></p>"
                    + "<p>This code is valid for 5 minutes. If you did not request this login, please ignore this email.</p>"
                    + "<br/>"
                    + "<p>Regards,<br/>The CertifyMe Team</p>";

            helper.setText(content, true);

            mailSender.send(message);
            System.out.println("EMAIL SENT SUCCESSFULLY");

        } catch (Exception e) {
            System.out.println("EMAIL FAILED");
            e.printStackTrace();
        }
    }
}
