import {
  Injectable,
  NestMiddleware,
  UnauthorizedException,
} from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from 'src/types/jwt-payload.interface';

@Injectable()
export class AuthMiddleware implements NestMiddleware {
  constructor(private readonly configService: ConfigService) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
      const token = authHeader.split(' ')[1]; // Bearer token

      try {
        const secretKey = this.configService.get<string>('JWT_SECRET_KEY');
        const decoded = jwt.verify(token, secretKey) as JwtPayload;

        if (typeof decoded === 'object' && 'userId' in decoded) {
          req.user = decoded;
        } else {
          throw new UnauthorizedException('Invalid token');
        }

        next();
      } catch (error) {
        throw new UnauthorizedException('Invalid token');
      }
    } else {
      throw new UnauthorizedException('No token provided');
    }
  }
}
