import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from '../users/users.service';
import { ConfigService } from '@nestjs/config'; // For accessing environment variables

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private usersService: UsersService,
    private configService: ConfigService, // Inject ConfigService for JWT_SECRET access
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'), // Use access token secret
    });
  }

  async validate(payload: any) {
    // Check that the token type is 'access', deny if it's 'refresh'
    if (payload.type && payload.type !== 'access') {
      throw new UnauthorizedException('Invalid token type');
    }

    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException();
    }

    if (!user.emailConfirmed) {
      throw new UnauthorizedException('Email not confirmed');
    }

    if (!user.approved) {
      throw new UnauthorizedException('Account not approved'); // Deny access if the account is not approved
    }

    return user;
  }
}
