import { Controller, Get, Request, Res } from '@nestjs/common';
import { AppService } from './app.service';
import { Request as ExpressRequest, Response } from 'express';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(@Request() req: ExpressRequest, @Res() response: Response) {
    return this.appService.getHello(req['user']['id'], response);
  }
}
