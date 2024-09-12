import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: 'gmail', // Change this if you're using another service like SendGrid, SES, etc.
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });
  }

  async sendEmail(to: string, subject: string, html: string) {
    await this.transporter.sendMail({
      to,
      subject,
      html,
    });
  }

  async sendEmailConfirmation(email: string, token: string) {
    const appUrl = process.env.APP_URL || 'http://localhost:3000'; // Fallback if APP_URL is not set
    const url = `${appUrl}/auth/confirm-email?token=${token}`;
    const html = `Please click <a href="${url}">here</a> to confirm your email. ${url}`;

    await this.sendEmail(email, 'Email Confirmation', html);
  }

  async sendPasswordReset(email: string, token: string) {
    const appUrl = process.env.APP_URL || 'http://localhost:3000'; // Fallback to localhost if APP_URL is not set
    const url = `${appUrl}/auth/reset-password?token=${token}`;
    const html = `Please click <a href="${url}">here</a> to reset your password. This link will expire in 1 hour.`;

    await this.sendEmail(email, 'Password Reset', html);
  }
}
