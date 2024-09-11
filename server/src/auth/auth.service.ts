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

  async validateUser(email: string, pass: string): Promise<User | null> {
    this.logger.log(`Validating user with email: ${email}`); // Log email being validated

    const user = await this.usersService.findByEmail(email);
    if (!user) {
      this.logger.warn(`User with email ${email} not found`); // Log if user not found
      return null;
    }

    const isPasswordValid = await bcrypt.compare(pass, user.password);
    this.logger.log(`Password comparison result for user ${email}: ${isPasswordValid}`); // Log password comparison result

    if (!isPasswordValid) {
      return null;
    }

    if (!user.emailConfirmed) {
      this.logger.warn(`User ${email} has not confirmed their email`); // Log if email is not confirmed
      throw new HttpException('Email not confirmed', HttpStatus.FORBIDDEN);
    }

    this.logger.log(`User ${email} validated successfully`); // Log successful validation
    return user;
  }

  async login(user: User) {
    this.logger.log(`Logging in user with email: ${user.email}`); // Log login attempt

    const payload = { sub: user.id, role: user.role };
    const token = this.jwtService.sign(payload);

    this.logger.log(`JWT generated for user ${user.email}`); // Log JWT generation
    return {
      access_token: token,
    };
  }

  async register(createUserDto: CreateUserDto, currentUser: User): Promise<User> {
    this.logger.log(`Registering new user with email: ${createUserDto.email}`); // Log registration attempt

    let allowedRoles: string[] = [];
    if (currentUser.role === 'admin') {
      allowedRoles = ['admin', 'office', 'guide', 'tourist'];
    } else if (currentUser.role === 'office') {
      allowedRoles = ['guide', 'tourist'];
    } else {
      this.logger.warn(`User ${currentUser.email} is not allowed to create new users with role: ${createUserDto.role}`);
      throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
    }

    if (!allowedRoles.includes(createUserDto.role)) {
      this.logger.warn(`Role ${createUserDto.role} is not allowed for user ${currentUser.email}`);
      throw new HttpException(`You cannot assign the role: ${createUserDto.role}`, HttpStatus.FORBIDDEN);
    }

    const existingUser = await this.usersService.findByEmail(createUserDto.email);
    if (existingUser) {
      this.logger.warn(`User with email ${createUserDto.email} already exists`);
      throw new HttpException('User with this email already exists', HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    this.logger.log(`Password for new user ${createUserDto.email} has been hashed`); // Log password hashing

    const newUser = new User();
    newUser.email = createUserDto.email;
    newUser.password = hashedPassword;
    newUser.role = createUserDto.role;
    newUser.emailConfirmed = false;

    const user = await this.usersService.create(newUser);

    const token = this.jwtService.sign({ email: user.email }, { expiresIn: '1d' });
    await this.emailService.sendEmailConfirmation(user.email, token);
    this.logger.log(`Confirmation email sent to ${user.email}`); // Log email confirmation sending

    return user;
  }

  async confirmEmail(token: string) {
    try {
      const payload = this.jwtService.verify(token);
      this.logger.log(`Confirming email for user with email: ${payload.email}`); // Log email confirmation

      const user = await this.usersService.findByEmail(payload.email);

      if (!user) {
        this.logger.warn(`User with email ${payload.email} not found during email confirmation`); // Log if user not found
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      user.emailConfirmed = true;
      await this.usersService.update(user.id, user);
      this.logger.log(`Email confirmed successfully for user ${user.email}`); // Log email confirmation success

      return { message: 'Email confirmed successfully.' };
    } catch (error) {
      this.logger.error(`Invalid or expired token during email confirmation: ${error.message}`); // Log token issue
      throw new HttpException('Invalid or expired token', HttpStatus.BAD_REQUEST);
    }
  }
}
