import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from 'src/types/jwt-payload.interface';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
      const token = authHeader.split(' ')[1]; // Bearer <token>

      try {
        const secretKey = this.configService.get<string>('JWT_SECRET_KEY');
        console.log('Token:', token);
        const decoded = jwt.verify(token, secretKey) as JwtPayload;
        console.log('Decoded:', decoded);

        if (typeof decoded === 'object' && 'userId' in decoded) {
          // const session = await this.prisma.session.findUnique({
          //   where: { token },
          // });

          // if (!session || session.expiresAt < new Date()) {
          //   // delete session if it's invalid
          //   await this.prisma.session.delete({
          //     where: { token },
          //   });
          //   throw new UnauthorizedException('Token has been revoked');
          // }

          req.user = decoded;
        } else {
          throw new UnauthorizedException('Invalid token');
        }

        next();
      } catch (error) {
        console.error('JWT Verification Error:', error);
        throw new UnauthorizedException('Invalid token error');
      }
    } else {
      throw new UnauthorizedException('No token provided');
    }
  }
}
