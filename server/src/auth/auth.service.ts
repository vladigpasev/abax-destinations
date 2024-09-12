import { Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { EmailService } from '../email/email.service';
import { User } from '../users/user.entity';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name); // Initialize Logger

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private emailService: EmailService,
  ) {}

  // Validate user credentials and ensure email is confirmed
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
      throw new HttpException('Account not approved', HttpStatus.FORBIDDEN); // Return forbidden if not approved
    }

    this.logger.log(`User ${email} validated successfully`);
    return user;
  }

  // Login method: generates JWT token for the user
  async login(user: User) {
    this.logger.log(`Logging in user with email: ${user.email}`);

    const payload = { sub: user.id, role: user.role };
    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(payload, { expiresIn: '7d' });

    this.logger.log(`JWT and refresh token generated for user ${user.email}`);

    // Include role in response to help with client-side RBAC
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

    // Get the role from the DTO or default to 'tourist'
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

    // Open registration for 'tourist', 'guide', and 'office'
    if (!currentUser) {
      if (role === 'admin') {
        this.logger.warn(
          `Unauthorized attempt to register user with role: ${role}`,
        );
        throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);
      }
      // Allow 'tourist', 'guide', and 'office' to register, but 'guide' and 'office' need approval
      const user = await this.usersService.create(newUser);
      const token = this.jwtService.sign(
        { email: user.email },
        { expiresIn: '1d' },
      );
      await this.emailService.sendEmailConfirmation(user.email, token);
      this.logger.log(`Confirmation email sent to ${user.email}`);
      return user;
    }

    // If an authenticated user is creating a new user, ensure they have the right permissions
    if (currentUser.role === 'admin') {
      // Admin can register any role, including other admins
      const user = await this.usersService.create(newUser);
      const token = this.jwtService.sign(
        { email: user.email },
        { expiresIn: '1d' },
      );
      await this.emailService.sendEmailConfirmation(user.email, token);
      this.logger.log(`Admin created user with role: ${role}`);
      return user;
    } else if (currentUser.role === 'office' && role === 'guide') {
      // Office can register guides
      const user = await this.usersService.create(newUser);
      const token = this.jwtService.sign(
        { email: user.email },
        { expiresIn: '1d' },
      );
      await this.emailService.sendEmailConfirmation(user.email, token);
      this.logger.log(`Office created guide`);
      return user;
    } else {
      this.logger.warn(
        `User ${currentUser.email} is not allowed to create new users with role: ${role}`,
      );
      throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
    }
  }

  private async createPrivilegedUser(
    createUserDto: CreateUserDto,
  ): Promise<User> {
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

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const newUser = new User();
    newUser.email = createUserDto.email;
    newUser.password = hashedPassword;
    newUser.role = createUserDto.role; // Assign the specific role
    newUser.emailConfirmed = false;

    const user = await this.usersService.create(newUser);

    const token = this.jwtService.sign(
      { email: user.email },
      { expiresIn: '1d' },
    );
    await this.emailService.sendEmailConfirmation(user.email, token);
    this.logger.log(`Confirmation email sent to ${user.email}`);

    return user;
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
      throw new HttpException(
        'Invalid or expired token',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // Refresh token logic
  async refreshToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken);
      this.logger.log(`Refreshing token for user with email: ${payload.email}`);

      const user = await this.usersService.findById(payload.sub);
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      const newAccessToken = this.jwtService.sign({
        sub: user.id,
        role: user.role,
      });
      return {
        access_token: newAccessToken,
      };
    } catch (error) {
      throw new HttpException(
        'Invalid or expired refresh token',
        HttpStatus.UNAUTHORIZED,
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

    // Съхраняваме токена и времето на изтичане в базата данни
    user.resetPasswordToken = resetToken;
    user.resetPasswordTokenExpiry = new Date(Date.now() + 3600 * 1000); // 1 час напред
    await this.usersService.update(user.id, user);

    await this.emailService.sendPasswordReset(user.email, resetToken);

    this.logger.log(`Password reset email sent to ${email}`);
  }

  // Reset Password: Validate reset token and set new password
  async resetPassword(token: string, newPassword: string): Promise<void> {
    const user = await this.usersService.findByResetPasswordToken(token);

    // Проверка дали потребителят съществува и дали токенът не е изтекъл
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

    // Зануляване на токена и времето му на изтичане, за да не може да се ползва отново
    user.resetPasswordToken = null;
    user.resetPasswordTokenExpiry = null;

    await this.usersService.update(user.id, user);

    this.logger.log(`Password reset successfully for user ${user.email}`);
  }
}
