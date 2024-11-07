import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Request,
  Res,
} from '@nestjs/common';
import { Request as ExpressRequest, Response } from 'express';
import { AuthService } from './auth.service';
import { SkipAuth } from './skip.auth';
import { LoginUserDto } from './dto/login.dto';
import { RegisterUserDto } from './dto/register.dto';
import { UpdatePsswordDto } from './dto/update.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @SkipAuth()
  @HttpCode(HttpStatus.OK)
  @Post('login')
  signIn(@Body() loginDto: LoginUserDto, @Res() response: Response) {
    return this.authService.signIn(loginDto, response);
  }

  @SkipAuth()
  @Post('register')
  register(@Body() registerDto: RegisterUserDto, @Res() response: Response) {
    return this.authService.register(registerDto, response);
  }

  @Post('verify')
  verify(
    @Body() body: { otp: number },
    @Request() req: ExpressRequest,
    @Res() response: Response,
  ) {
    return this.authService.verifyEmail(
      body?.otp,
      req['user']['email'],
      response,
    );
  }

  @Post('update/password')
  updatePassword(
    @Body() body: UpdatePsswordDto,
    @Request() req: ExpressRequest,
    @Res() response: Response,
  ) {
    return this.authService.updatePassword(
      body,
      req['user']['email'],
      response,
    );
  }

  @SkipAuth()
  @Post('reset/password/email')
  resetPasswordEmail(
    @Body() body: { email: string },
    @Res() response: Response,
  ) {
    return this.authService.resetPasswordEmail(body?.email, response);
  }

  @SkipAuth()
  @Post('reset/password/verify')
  resetPasswordVerifyOtp(
    @Body() body: { email: string; otp: number },
    @Res() response: Response,
  ) {
    return this.authService.resetPasswordOtp(body, response);
  }

  @SkipAuth()
  @Post('reset/password')
  resetPassword(
    @Body()
    body: { email: string; newPassword: string; confirmPassword: string },
    @Res() response: Response,
  ) {
    return this.authService.resetPassword(body, response);
  }

  @Get('resend/otp')
  resendOtp(@Request() req: ExpressRequest, @Res() response: Response) {
    return this.authService.resendOtp(req['user']['email'], response);
  }

  @Get('signout')
  signOut(@Request() req: ExpressRequest, @Res() response: Response) {
    return this.authService.signOut(req['user']['email'], response);
  }
}
