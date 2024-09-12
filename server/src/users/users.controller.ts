import {
  Controller,
  Get,
  Param,
  Patch,
  Body,
  UseGuards,
  Req,
  HttpException,
  HttpStatus,
  Query,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiQuery,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { UpdateUserDto } from './dto/update-user.dto';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'office', 'guide', 'tourist')
  @Get()
  @ApiOperation({ summary: 'Get all users with filters and sorting' })
  @ApiResponse({ status: 200, description: 'Users retrieved successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  @ApiQuery({
    name: 'role',
    required: false,
    type: String,
    enum: ['admin', 'office', 'guide', 'tourist'],
    description: 'Filter by user role',
  })
  @ApiQuery({
    name: 'sortByEmail',
    required: false,
    enum: ['asc', 'desc'],
    description: 'Sort users by email (asc for A-Z, desc for Z-A)',
  })
  @ApiQuery({
    name: 'sortByCreatedAt',
    required: false,
    enum: ['asc', 'desc'],
    description:
      'Sort users by creation date (asc for oldest first, desc for newest first)',
  })
  @ApiBearerAuth()
  async getAllUsers(
    @Req() req,
    @Query('role') role?: string,
    @Query('sortByEmail') sortByEmail?: 'asc' | 'desc',
    @Query('sortByCreatedAt') sortByCreatedAt?: 'asc' | 'desc',
  ) {
    return this.usersService.getUsersByFiltersAndSorting(
      req.user,
      role,
      sortByEmail,
      sortByCreatedAt,
    );
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'office', 'guide', 'tourist')
  @Get(':uuid') // Replaced id with uuid
  @ApiOperation({ summary: 'Get user by UUID' })
  @ApiResponse({ status: 200, description: 'User retrieved successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  @ApiBearerAuth()
  async getUserById(@Param('uuid') uuid: string, @Req() req) {
    const user = await this.usersService.findByUuid(uuid);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    if (
      req.user.role === 'admin' ||
      (req.user.role === 'office' &&
        (user.role === 'guide' ||
          user.role === 'tourist' ||
          user.uuid === req.user.uuid)) ||
      req.user.uuid === user.uuid
    ) {
      return user;
    }

    throw new HttpException('Forbidden', HttpStatus.FORBIDDEN);
  }

  @Patch(':uuid') // Replaced id with uuid
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin', 'office', 'guide', 'tourist')
  @ApiOperation({ summary: 'Update user by UUID (Patch request)' })
  @ApiResponse({ status: 200, description: 'User updated successfully' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  @ApiBody({ type: UpdateUserDto })
  @ApiBearerAuth()
  async updateUser(
    @Param('uuid') uuid: string,
    @Body() updateUserDto: UpdateUserDto,
    @Req() req,
  ) {
    try {
      return await this.usersService.updateUserByRoleAndAccess(
        uuid,
        updateUserDto,
        req.user,
      );
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.FORBIDDEN);
    }
  }
}
