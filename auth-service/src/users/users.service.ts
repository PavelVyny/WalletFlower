// users/users.service.ts

import { Injectable, Inject } from '@nestjs/common'; // Import Inject
import { IUserRepository } from './interfaces/user.repository.interface';

@Injectable()
export class UsersService {
  constructor(
    @Inject('IUserRepository') // Use Inject with the custom provider token
    private readonly userRepository: IUserRepository,
  ) {}

  async createUser(email: string, password: string) {
    return this.userRepository.createUser(email, password);
  }

  async findByEmail(email: string) {
    return this.userRepository.findByEmail(email);
  }
}
