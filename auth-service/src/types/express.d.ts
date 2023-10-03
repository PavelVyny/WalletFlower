import { JwtPayload } from './jwt-payload.interface';

declare module 'express' {
  export interface Request {
    user?: JwtPayload;
  }
}
