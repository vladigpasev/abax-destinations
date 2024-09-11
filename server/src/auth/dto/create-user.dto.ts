import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({ description: 'Email of the user' })
  @IsEmail()
  email: string;

  @ApiProperty({ description: 'Password of the user' })
  @IsNotEmpty()
  @MinLength(8)
  password: string;

  @ApiProperty({ description: 'Roles of the user' })
  @IsString({ each: true })
  roles: string[];
}
``