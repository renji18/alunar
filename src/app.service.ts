import { Injectable } from '@nestjs/common';
import { PrismaService } from './prisma.service';
import { customGoneError, customSuccess } from './utils/util.functions';
import { Response } from 'express';

@Injectable()
export class AppService {
  constructor(private prisma: PrismaService) {}

  async getHello(userId: string, response: Response): Promise<any> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        auth: true,
      },
    });
    if (!user) return customGoneError(response, 'User');

    return customSuccess(response, user);
  }
}
