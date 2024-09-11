import { IsEmail, IsNotEmpty, IsString, IsIn, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({ description: 'Email of the user' })
  @IsEmail()
  email: string;

  @ApiProperty({ description: 'Password of the user' })
  @IsNotEmpty()
  @MinLength(8)
  password: string;

  @ApiProperty({ 
    description: 'Role of the user', 
    enum: ['admin', 'office', 'guide', 'tourist'] 
  })
  @IsString()
  @IsIn(['admin', 'office', 'guide', 'tourist'])
  role: string;
}
