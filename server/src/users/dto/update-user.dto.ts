import {
  IsBoolean,
  IsOptional,
  IsIn,
  IsString,
  IsEmail,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateUserDto {
  @ApiPropertyOptional({
    description: 'Role of the user (can only be changed by Admin or Office)',
    enum: ['admin', 'office', 'guide', 'tourist'],
  })
  @IsOptional()
  @IsIn(['admin', 'office', 'guide', 'tourist'], { message: 'Invalid role' })
  role?: string;

  @ApiPropertyOptional({
    description:
      'Indicates whether the user has confirmed their email (Admin only)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  emailConfirmed?: boolean;

  @ApiPropertyOptional({
    description: 'Approval status of the user (Admin or Office for guides)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  approved?: boolean;

  @ApiPropertyOptional({
    description: 'Reset password token (cannot be updated)',
    example: 'token123',
    readOnly: true,
  })
  resetPasswordToken?: string;

  @ApiPropertyOptional({
    description:
      'Timestamp for reset password token expiry (cannot be updated)',
    example: '2024-09-12T09:50:45.000Z',
    readOnly: true,
  })
  resetPasswordTokenExpiry?: Date;

  @ApiPropertyOptional({
    description: 'Email of the user (cannot be updated)',
    example: 'user@example.com',
    readOnly: true,
  })
  @IsEmail()
  email?: string;

  @ApiPropertyOptional({
    description: 'Password of the user (cannot be updated)',
    example: 'password123',
    readOnly: true,
  })
  password?: string;
}
