// users/users.service.ts

import { Injectable } from '@nestjs/common';
import { IUserRepository } from './interfaces/user.repository.interface';

@Injectable()
export class UsersService {
  constructor(private readonly userRepository: IUserRepository) {}

  async createUser(email: string, password: string) {
    return this.userRepository.createUser(email, password);
  }

  async findByEmail(email: string) {
    return this.userRepository.findByEmail(email);
  }
}
