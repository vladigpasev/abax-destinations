import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
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
    }).catch(err => {
      throw new Error('Failed to send email: ' + err.message);
    });
  }

  async sendEmailConfirmation(email: string, token: string) {
    const url = `${process.env.APP_URL}/auth/confirm-email?token=${token}`;
    const html = `Please click <a href="${url}">here</a> to confirm your email.`;

    await this.sendEmail(email, 'Email Confirmation', html);
  }
}
