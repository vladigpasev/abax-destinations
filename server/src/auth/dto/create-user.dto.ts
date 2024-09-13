import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsIn,
  MinLength,
  IsPhoneNumber,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({
    description: 'Email of the user',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Password of the user',
    example: 'password123',
    minLength: 8,
  })
  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;

  @ApiProperty({
    description: 'Role of the user',
    enum: ['admin', 'office', 'guide', 'tourist'],
    required: false,
  })
  @IsString()
  @IsIn(['admin', 'office', 'guide', 'tourist'], { message: 'Invalid role' })
  role?: string;

  @ApiProperty({
    description: 'First name of the user',
    example: 'John',
  })
  @IsNotEmpty({ message: 'First name is required' })
  firstName: string;

  @ApiProperty({
    description: 'Last name of the user',
    example: 'Doe',
  })
  @IsNotEmpty({ message: 'Last name is required' })
  lastName: string;

  @ApiProperty({
    description: 'Phone number of the user',
    example: '+1234567890',
  })
  @IsPhoneNumber(null, { message: 'Invalid phone number' })
  @IsNotEmpty({ message: 'Phone number is required' })
  phone: string;
}
