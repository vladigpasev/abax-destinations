import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
  @ApiProperty({
    description: 'Email to request a password reset',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;
}
