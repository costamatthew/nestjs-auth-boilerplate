import { Injectable } from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';

@Injectable()
export class AuthService {
  constructor() {}

  async signup(dto: AuthDto) {
    return { message: 'TEST' };
  }

  async signin() {
    return { message: 'TEST' };
  }

  async signout() {
    return { message: 'TEST' };
  }
}
