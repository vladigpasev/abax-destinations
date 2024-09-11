import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { User } from '../users/user.entity';
import { CreateUserDto } from './dto/create-user.dto'; // Импорт на DTO

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, pass: string): Promise<User | null> {
    const user = await this.usersService.findByEmail(email);
    if (user && await bcrypt.compare(pass, user.password)) {
      return user;
    }
    return null;
  }

  async login(user: User) {
    const payload = { sub: user.id, roles: user.roles };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async register(createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

    // Създаване на нов обект от тип User
    const newUser = new User();
    newUser.email = createUserDto.email;
    newUser.password = hashedPassword;
    newUser.roles = createUserDto.roles;

    // Запис в базата данни
    return this.usersService.create(newUser);
  }
}
