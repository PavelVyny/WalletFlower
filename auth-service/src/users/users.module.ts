import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { PrismaUserRepository } from './repositories/prisma.user.repository';
import { PrismaService } from 'prisma/prisma.service';

@Module({
  providers: [
    UsersService,
    PrismaService,
    {
      provide: 'IUserRepository',
      useClass: PrismaUserRepository,
    },
  ],
  exports: ['IUserRepository', UsersService],
})
export class UsersModule {}
