import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenDto {
  @ApiProperty({
    description: 'Refresh token',
    example: 'your-refresh-token-here',
  })
  @IsString()
  @IsNotEmpty()
  refresh_token: string;
}
