import { Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { EmailService } from '../email/email.service';
import { User } from '../users/user.entity';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private emailService: EmailService,
  ) {}
  private generateRandomToken(): string {
    return randomBytes(32).toString('hex'); // 32 bytes = 64 characters hex string
  }

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

  // Login method: generates JWT and refresh token for the user
  async login(user: User) {
    this.logger.log(`Logging in user with email: ${user.email}`);

    const payload = { sub: user.id, role: user.role };
    const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });

    const refreshToken = this.generateRandomToken();  // Generate random refresh token

    // Save refresh token securely in the database
    await this.usersService.update(user.id, { refreshToken });

    this.logger.log(`JWT and refresh token generated for user ${user.email}`);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      role: user.role, // Return the user role for RBAC in the client
    };
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

  // Refresh token logic with token rotation
  async refreshToken(refreshToken: string) {
    try {
      // Lookup the user by the refresh token
      const user = await this.usersService.findByRefreshToken(refreshToken);

      if (!user) {
        this.logger.warn(`Invalid refresh token`);
        throw new HttpException('Invalid refresh token', HttpStatus.UNAUTHORIZED);
      }

      this.logger.log(`Refreshing token for user with ID: ${user.id}`);

      // Generate new access token
      const payload = { sub: user.id, role: user.role };
      const newAccessToken = this.jwtService.sign(payload, { expiresIn: '15m' });

      // Generate a new refresh token (rotate the refresh token)
      const newRefreshToken = this.generateRandomToken();

      // Update the user's refresh token in the database
      await this.usersService.update(user.id, { refreshToken: newRefreshToken });

      this.logger.log(`Tokens refreshed for user with ID: ${user.id}`);

      return {
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
      };
    } catch (error) {
      this.logger.error(`Failed to refresh token: ${error.message}`);
      throw new HttpException('Invalid or expired refresh token', HttpStatus.UNAUTHORIZED);
    }
  }

  // Logout: Invalidate refresh token
  async logout(userId: number): Promise<void> {
    this.logger.log(`Logging out user with ID: ${userId}`);

    // Invalidate the refresh token by removing it from the database
    await this.usersService.update(userId, { refreshToken: null });

    this.logger.log(`Refresh token invalidated for user with ID: ${userId}`);
  }


  // Confirm email logic
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
      throw new HttpException('Invalid or expired token', HttpStatus.BAD_REQUEST);
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
      throw new HttpException('Email already confirmed', HttpStatus.BAD_REQUEST);
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
      throw new HttpException('Invalid or expired token', HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    user.resetPasswordToken = null;
    user.resetPasswordTokenExpiry = null;

    await this.usersService.update(user.id, user);

    this.logger.log(`Password reset successfully for user ${user.email}`);
  }
}
