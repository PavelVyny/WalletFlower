import { User } from '@prisma/client';

export interface IUserRepository {
  createUser(email: string, password: string): Promise<User>;
  findByEmail(email: string): Promise<User | null>;
}
