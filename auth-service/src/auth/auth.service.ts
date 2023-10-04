import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
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

@Injectable()
export class AuthService {
  constructor(
    @Inject('IUserRepository') // Inject using the custom provider token
    private readonly userRepository: PrismaUserRepository,
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async register(
    registerDto: RegisterDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const { email, password } = registerDto;

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
      const user = await this.userRepository.createUser(email, hashedPassword);
      const payload = { email: user.email, id: user.id };

      const accessToken = this.generateJwt(payload, '5m');
      const refreshToken = this.generateJwt(payload, '30d');

      // Session creation
      await this.prisma.session.create({
        data: {
          userId: user.id,
          token: refreshToken,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days in ms
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
      const payload = { email: user.email, id: user.id };

      const accessToken = this.generateJwt(payload, '5m');
      const refreshToken = this.generateJwt(payload, '30d');

      // Session creation
      await this.prisma.session.create({
        data: {
          userId: user.id,
          token: refreshToken,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days in ms
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

      const payload = { email: user.email, id: user.id };

      const newAccessToken = this.generateJwt(payload, '5m');
      const newRefreshToken = this.generateJwt(payload, '30d');

      // Update the session
      await this.prisma.session.update({
        where: { token: refreshToken },
        data: {
          token: newRefreshToken,
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        },
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private generateJwt(payload: any, expiresIn: string): string {
    const secretKey = this.configService.get<string>('JWT_SECRET_KEY');
    return jwt.sign(payload, secretKey, { expiresIn });
  }
}
