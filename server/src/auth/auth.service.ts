import { Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { EmailService } from '../email/email.service';
import { User } from '../users/user.entity';
import { randomBytes } from 'crypto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private configService: ConfigService,
  ) {}

  // Validate user credentials and ensure email is confirmed and account is approved
  async validateUser(email: string, pass: string): Promise<User | null> {
    this.logger.log(`Validating user with email: ${email}`);

    const user = await this.usersService.findByEmail(email);
    if (!user) {
      this.logger.warn(`User with email ${email} not found`);
      return null;
    }

    const isPasswordValid = await bcrypt.compare(pass, user.password);
    this.logger.log(
      `Password comparison result for user ${email}: ${isPasswordValid}`,
    );

    if (!isPasswordValid) {
      return null;
    }

    if (!user.emailConfirmed) {
      this.logger.warn(`User ${email} has not confirmed their email`);
      throw new HttpException('Email not confirmed', HttpStatus.FORBIDDEN);
    }

    if (!user.approved) {
      this.logger.warn(`User ${email} has not been approved`);
      throw new HttpException('Account not approved', HttpStatus.FORBIDDEN);
    }

    this.logger.log(`User ${email} validated successfully`);
    return user;
  }

  // Register method: creates a new user and sends an email confirmation
  async register(
    createUserDto: CreateUserDto,
    currentUser?: User,
  ): Promise<User> {
    this.logger.log(`Registering new user with email: ${createUserDto.email}`);

    const role = createUserDto.role || 'tourist';

    // Check if the user already exists by email
    const existingUser = await this.usersService.findByEmail(
      createUserDto.email,
    );
    if (existingUser) {
      this.logger.warn(`User with email ${createUserDto.email} already exists`);
      throw new HttpException(
        'User with this email already exists',
        HttpStatus.BAD_REQUEST,
      );
    }

    // Hash the user's password
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    this.logger.log(
      `Password for new user ${createUserDto.email} has been hashed`,
    );

    // Create a new user instance
    const newUser = new User();
    newUser.email = createUserDto.email;
    newUser.password = hashedPassword;
    newUser.role = role;
    newUser.emailConfirmed = false;

    // Auto-approve tourist role, other roles require approval
    if (role === 'tourist') {
      newUser.approved = true; // Automatically approve tourists
    } else {
      newUser.approved = false; // Roles like 'guide', 'office', and 'admin' need approval
    }

    // Save new user and send email confirmation
    const user = await this.usersService.create(newUser);
    const token = this.jwtService.sign(
      { email: user.email },
      { expiresIn: '1d' },
    );
    await this.emailService.sendEmailConfirmation(user.email, token);
    this.logger.log(`Confirmation email sent to ${user.email}`);

    return user;
  }

  async login(user: User) {
    const payload = { sub: user.id, role: user.role, type: 'access' };
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
      secret: this.configService.get<string>('JWT_SECRET'),
    });

    const refreshTokenPayload = {
      sub: user.id,
      type: 'refresh',
      version: user.refreshTokenVersion, // Include the token version
    };
    const refreshToken = this.jwtService.sign(refreshTokenPayload, {
      expiresIn: '7d',
      secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
    });

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      //role: user.role,
    };
  }

  // Refresh token logic with token rotation
  async refreshToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
      });

      if (payload.type !== 'refresh') {
        throw new HttpException('Invalid token type', HttpStatus.UNAUTHORIZED);
      }

      const user = await this.usersService.findById(payload.sub);
      if (!user || user.refreshTokenVersion !== payload.version) {
        this.logger.warn(`Invalid refresh token version`);
        throw new HttpException(
          'Invalid refresh token',
          HttpStatus.UNAUTHORIZED,
        );
      }

      this.logger.log(`Refreshing token for user with ID: ${user.id}`);

      // Generate new access and refresh tokens
      const newAccessToken = this.jwtService.sign(
        { sub: user.id, role: user.role },
        {
          expiresIn: '15m',
          secret: this.configService.get<string>('JWT_SECRET'),
        },
      );

      const newRefreshTokenPayload = {
        sub: user.id,
        type: 'refresh',
        version: user.refreshTokenVersion, // Include the latest version
      };
      const newRefreshToken = this.jwtService.sign(newRefreshTokenPayload, {
        expiresIn: '7d',
        secret: this.configService.get<string>('JWT_REFRESH_TOKEN_SECRET'),
      });

      return {
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
      };
    } catch (error) {
      this.logger.error(`Failed to refresh token: ${error.message}`);
      throw new HttpException(
        'Invalid or expired refresh token',
        HttpStatus.UNAUTHORIZED,
      );
    }
  }

  async logout(userId: number): Promise<void> {
    this.logger.log(`Logging out user with ID: ${userId}`);

    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Clear refreshToken and increment the version to invalidate all existing tokens
    await this.usersService.update(userId, {
      refreshToken: null, // Optional, but good practice for security
      refreshTokenVersion: user.refreshTokenVersion + 1,
    });

    this.logger.log(
      `User with ID: ${userId} has been logged out and tokens invalidated.`,
    );
  }

  async confirmEmail(token: string) {
    try {
      const payload = this.jwtService.verify(token);
      this.logger.log(`Confirming email for user with email: ${payload.email}`);

      const user = await this.usersService.findByEmail(payload.email);

      if (!user) {
        this.logger.warn(
          `User with email ${payload.email} not found during email confirmation`,
        );
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      user.emailConfirmed = true;
      await this.usersService.update(user.id, user);
      this.logger.log(`Email confirmed successfully for user ${user.email}`);

      return { message: 'Email confirmed successfully.' };
    } catch (error) {
      this.logger.error(
        `Invalid or expired token during email confirmation: ${error.message}`,
      );
      throw new HttpException(
        'Invalid or expired token',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  async resendConfirmationEmail(email: string): Promise<void> {
    this.logger.log(`Resending confirmation email to: ${email}`);

    const user = await this.usersService.findByEmail(email);
    if (!user) {
      this.logger.warn(`User with email ${email} not found`);
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    if (user.emailConfirmed) {
      this.logger.warn(
        `User with email ${email} has already confirmed their email`,
      );
      throw new HttpException(
        'Email already confirmed',
        HttpStatus.BAD_REQUEST,
      );
    }

    const token = this.jwtService.sign(
      { email: user.email },
      { expiresIn: '1d' },
    );
    await this.emailService.sendEmailConfirmation(user.email, token);

    this.logger.log(`Confirmation email resent to ${email}`);
  }

  // Forgot Password: Generate reset token and send email
  async forgotPassword(email: string): Promise<void> {
    const user = await this.usersService.findByEmail(email);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    const resetToken = this.jwtService.sign(
      { email: user.email },
      { expiresIn: '1h' },
    );

    user.resetPasswordToken = resetToken;
    user.resetPasswordTokenExpiry = new Date(Date.now() + 3600 * 1000); // 1 hour ahead
    await this.usersService.update(user.id, user);

    await this.emailService.sendPasswordReset(user.email, resetToken);

    this.logger.log(`Password reset email sent to ${email}`);
  }

  // Reset Password: Validate reset token and set new password
  async resetPassword(token: string, newPassword: string): Promise<void> {
    const user = await this.usersService.findByResetPasswordToken(token);

    if (
      !user ||
      user.resetPasswordToken !== token ||
      user.resetPasswordTokenExpiry < new Date()
    ) {
      throw new HttpException(
        'Invalid or expired token',
        HttpStatus.BAD_REQUEST,
      );
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    user.resetPasswordToken = null;
    user.resetPasswordTokenExpiry = null;

    await this.usersService.update(user.id, user);

    this.logger.log(`Password reset successfully for user ${user.email}`);
  }
}
