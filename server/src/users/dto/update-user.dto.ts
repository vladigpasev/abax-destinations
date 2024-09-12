import {
  IsOptional,
  IsEmail,
  IsString,
  IsIn,
  MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateUserDto {
  @ApiProperty({
    description: 'Email of the user',
    required: false,
    example: 'user@example.com',
  })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiProperty({
    description: 'Password of the user',
    required: false,
    example: 'newpassword123',
  })
  @IsOptional()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password?: string;

  @ApiProperty({
    description: 'Role of the user',
    required: false,
    enum: ['admin', 'office', 'guide', 'tourist'],
  })
  @IsOptional()
  @IsString()
  @IsIn(['admin', 'office', 'guide', 'tourist'])
  role?: string;
}
