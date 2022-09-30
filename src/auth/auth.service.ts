import { BadRequestException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

import { PrismaService } from 'prisma/prisma.service';

import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    const { email, password } = dto;

    const foundUser = await this.prisma.user.findUnique({ where: { email } });
    if (foundUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.prisma.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return { message: 'signup was succefull', status: 201 };
  }

  async signin() {
    return { message: 'TEST' };
  }

  async signout() {
    return { message: 'TEST' };
  }

  async hashPassword(password: string) {
    const salrOrRounds = 10;
    const hashedPassword = await bcrypt.hash(password, salrOrRounds);

    return hashedPassword;
  }
}
