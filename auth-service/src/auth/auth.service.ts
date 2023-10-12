import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as ms from 'ms';
import {
  Injectable,
  Inject,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { PrismaUserRepository } from 'src/users/repositories/prisma.user.repository';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from 'prisma/prisma.service';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {
  private refreshTokenExpiration: string;
  private accessTokenExpiration: string;

  constructor(
    @Inject('IUserRepository') // Inject using the custom provider token
    private readonly userRepository: PrismaUserRepository,
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    this.refreshTokenExpiration = this.configService.get<string>(
      'JWT_REFRESH_TOKEN_EXPIRATION',
      '30d',
    );

    this.accessTokenExpiration = this.configService.get<string>(
      'JWT_ACCESS_TOKEN_EXPIRATION',
      '5m',
    );
  }

  async register(
    registerDto: RegisterDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const { email, password } = registerDto;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const user = await this.userRepository.createUser(email, hashedPassword);
      const tokens = await this.generateTokens(user);
      const { accessToken, refreshToken } = tokens;

      // Session creation
      await this.prisma.session.create({
        data: {
          userId: user.id,
          token: refreshToken,
          expiresAt: this.getExpirationDate(this.refreshTokenExpiration),
        },
      });

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email already exists');
      }
      throw error;
    }
  }

  async login(
    loginDto: LoginDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const { email, password } = loginDto;
    const user = await this.userRepository.findByEmail(email);

    if (user && (await bcrypt.compare(password, user.password))) {
      const tokens = await this.generateTokens(user);
      const { accessToken, refreshToken } = tokens;

      // Session creation
      await this.prisma.session.create({
        data: {
          userId: user.id,
          token: refreshToken,
          expiresAt: this.getExpirationDate(this.refreshTokenExpiration),
        },
      });

      return {
        accessToken,
        refreshToken,
      };
    } else {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async logout(refreshToken: string): Promise<{ message: string }> {
    const secretKey = this.configService.get<string>('JWT_SECRET_KEY');

    try {
      // Verify the refresh token
      jwt.verify(refreshToken, secretKey) as JwtPayload;

      // Delete the session
      await this.prisma.session.delete({
        where: { token: refreshToken },
      });

      return { message: 'Logged out successfully' };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async logoutAll(
    userId: number,
    currentRefreshToken: string,
  ): Promise<{ message: string }> {
    await this.prisma.session.deleteMany({
      where: {
        userId: userId,
        token: {
          not: currentRefreshToken, // exclude current session from deleting
        },
      },
    });

    return { message: 'Logged out from all devices' };
  }

  async refresh(
    refreshToken: string,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const secretKey = this.configService.get<string>('JWT_SECRET_KEY');

    try {
      // Verify the refresh token
      const decoded = jwt.verify(refreshToken, secretKey) as JwtPayload;
      // Check the session
      const session = await this.prisma.session.findUnique({
        where: { token: refreshToken },
      });

      if (!session || session.expiresAt < new Date()) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Check the user
      const user = await this.userRepository.findByEmail(decoded.email);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      const newTokens = await this.generateTokens(user);

      // Update the session
      await this.prisma.session.update({
        where: { token: refreshToken },
        data: {
          token: newTokens.refreshToken,
          expiresAt: this.getExpirationDate(this.refreshTokenExpiration),
        },
      });

      return {
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private generateJwt(payload: any, expiresIn: string): string {
    const secretKey = this.configService.get<string>('JWT_SECRET_KEY');
    return jwt.sign(payload, secretKey, { expiresIn });
  }

  private async generateTokens(
    user: User,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const payload = { email: user.email, userId: user.id };
    const accessToken = this.generateJwt(payload, this.accessTokenExpiration);
    const refreshToken = this.generateJwt(payload, this.refreshTokenExpiration);

    return { accessToken, refreshToken };
  }

  private getExpirationDate(expirationTime: string): Date {
    return new Date(Date.now() + ms(expirationTime));
  }
}
