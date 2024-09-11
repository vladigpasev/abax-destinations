import { Controller, Post, Body, Get, Query, UseGuards, Req, HttpException, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login.dto';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';
import { Roles } from './roles.decorator';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
@ApiOperation({ summary: 'Login a user' })
@ApiResponse({ status: 200, description: 'User successfully logged in.' })
@ApiResponse({ status: 401, description: 'Invalid credentials.' })
@ApiBody({ type: LoginDto })
async login(@Body() loginDto: LoginDto) {
  console.log('Login controller reached'); // Add this log to see if the controller is hit
  const user = await this.authService.validateUser(loginDto.email, loginDto.password);
  if (!user) {
    console.log('Invalid credentials'); // Log when credentials are invalid
    throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
  }
  console.log('Valid credentials'); // Log when credentials are valid
  return this.authService.login(user);
}


  @Post('register')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'office')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User successfully registered.' })
  @ApiResponse({ status: 400, description: 'Invalid input.' })
  @ApiResponse({ status: 403, description: 'Forbidden.' })
  @ApiBody({ type: CreateUserDto })
  async register(@Body() createUserDto: CreateUserDto, @Req() req) {
    return this.authService.register(createUserDto, req.user);
  }

  @Get('confirm-email')
  @ApiOperation({ summary: 'Confirm user email' })
  @ApiResponse({ status: 200, description: 'Email confirmed successfully.' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token.' })
  async confirmEmail(@Query('token') token: string) {
    return this.authService.confirmEmail(token);
  }
}
