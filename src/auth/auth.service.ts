import { Injectable, NotFoundException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma.service';
import { RegisterUserDto } from './dto/register.dto';
import { Request as ExpressRequest, Response } from 'express';
import * as bcrypt from 'bcryptjs';
import * as nodemailer from 'nodemailer';
import {
  customError,
  customGoneError,
  customSuccess,
  findUserViaEmail,
} from 'src/utils/util.functions';
import { LoginUserDto } from './dto/login.dto';
import { UpdatePsswordDto } from './dto/update.dto';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
  ) {}

  private validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  private generateOTP() {
    const otp = Math.floor(1000 + Math.random() * 9000);
    return otp;
  }

  private async sendEmail(email: string, OTP: number): Promise<any> {
    try {
      const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: Number(process.env.EMAIL_PORT),
        secure: true,
        auth: {
          user: process.env.EMAIL_AUTH_USER,
          pass: process.env.EMAIL_AUTH_PASS,
        },
      });
      const mailOptions = {
        from: `${process.env.EMAIL_SENDER_NAME} ${process.env.EMAIL_SENDER_EMAIL}`,
        to: email,
        subject: process.env.EMAIL_SUBJECT,
        html: `
        <!DOCTYPE html>
        <html lang="en">
        <body>
        <div>
          <p>Dear User,</p>
          <p>Your OTP for verifying your Email at ALunar is <strong>${OTP}</strong></p>
          <p>This OTP would be valid only for 15 minutes.</p>
          <br/>
          <p>Thank You,</p>
          <p>ALunar</p>
        </div>
        </body>
        </html>
      `,
      };
      await transporter.sendMail(mailOptions);
    } catch (error) {
      throw new Error(error);
    }
  }

  async register(
    registerData: RegisterUserDto,
    response: Response,
  ): Promise<void> {
    const emailSearch = await findUserViaEmail(
      registerData?.email,
      this.prisma,
    );

    if (emailSearch) return customError(response, 'Email already exists');

    if (!this.validateEmail(registerData?.email))
      return customError(response, 'Please Provide a Valid Email');

    if (
      registerData?.password !== registerData?.confirmPassword ||
      registerData?.password === ''
    )
      return customError(response, 'Please provide your passwords');

    const hashedPassword = await bcrypt.hash(registerData?.password, 10);
    const OTP = this.generateOTP();
    const hashedOtp = await bcrypt.hash(String(OTP), 10);

    const createdUser = await this.prisma.user.create({
      data: {
        email: registerData?.email,
        name: registerData?.name,
        dob: registerData?.dob,
        location: registerData?.location,
        subscribed: registerData?.subscribed || false,
        auth: {
          create: {
            emailVerified: false,
            password: hashedPassword,
            otp: hashedOtp,
            otpTimeStamp: new Date(Date.now()),
            isLoggedIn: true,
            isAdmin: registerData?.isAdmin || false,
          },
        },
      },
    });

    const payload = { id: createdUser?.id, email: createdUser.email };
    const accessToken = await this.jwtService.signAsync(payload);

    await this.prisma.auth.update({
      where: {
        userId: createdUser?.id,
      },
      data: {
        token: Buffer.from(accessToken, 'utf-8'),
      },
    });

    await this.sendEmail(createdUser?.email, OTP);
    response
      .cookie(process.env.COOKIE_ACCESS_TOKEN, accessToken, {
        httpOnly: true,
        expires: new Date(Date.now() + 3 * 30 * 24 * 60 * 60 * 1000),
        secure: true,
        sameSite: 'none',
      })
      .json({
        success: 'An OTP has been send to your email for verification',
      });
  }

  async verifyEmail(
    otp: number,
    email: ExpressRequest,
    response: Response,
  ): Promise<any> {
    const userExists = await findUserViaEmail(String(email), this.prisma);

    if (userExists?.auth?.emailVerified)
      return customError(
        response,
        'Your Email Is Already Verified, Try Logging In',
      );

    const otpTS = userExists?.auth?.otpTimeStamp;

    const timeDifferenceInMinutes =
      ((new Date() as any) - (otpTS as any)) / (1000 * 60);

    if (timeDifferenceInMinutes > 15) {
      return customError(response, 'Your OTP has expired, regenerate OTP');
    }

    const isOtpMatched = await bcrypt.compare(
      String(otp),
      userExists?.auth?.otp,
    );

    if (isOtpMatched) {
      await this.prisma.auth.update({
        where: { id: userExists?.auth?.id },
        data: { emailVerified: true, otp: '' },
      });
      return customSuccess(response);
    } else {
      return customError(response, 'Invalid OTP');
    }
  }

  async signIn(loginData: LoginUserDto, response: Response): Promise<void> {
    const user = await findUserViaEmail(loginData?.email, this.prisma);
    if (!user) return customError(response, 'Invalid Username or Password');

    const isPasswordMatched = await bcrypt.compare(
      loginData?.password,
      user?.auth?.password,
    );
    if (!isPasswordMatched) return customError(response, 'Invalid Password');

    let success = 'User Signed In Successfully';
    if (!user?.auth?.emailVerified) {
      const OTP = this.generateOTP();
      const hashedOtp = await bcrypt.hash(String(OTP), 10);
      await this.sendEmail(loginData?.email, OTP);
      await this.prisma.auth.update({
        where: { id: user?.auth?.id },
        data: {
          otp: hashedOtp,
          otpTimeStamp: new Date(Date.now()),
        },
      });
      success = 'An OTP has been sent to you, Please Verify Your Email';
    }

    await this.prisma.auth.update({
      where: { id: user?.auth?.id },
      data: {
        isLoggedIn: true,
      },
    });

    const payload = { id: user?.id, email: user.email };
    const accessToken = await this.jwtService.signAsync(payload);

    await this.prisma.auth.update({
      where: { userId: user?.id },
      data: {
        token: Buffer.from(accessToken, 'utf-8'),
      },
    });

    response
      .cookie(process.env.COOKIE_ACCESS_TOKEN, accessToken, {
        httpOnly: true,
        expires: new Date(Date.now() + 3 * 30 * 24 * 60 * 60 * 1000),
        secure: true,
        sameSite: 'none',
      })
      .json({ success });
  }

  async updatePassword(
    data: UpdatePsswordDto,
    email: string,
    response: Response,
  ): Promise<any> {
    const userExists = await findUserViaEmail(String(email), this.prisma);

    if (!userExists?.auth?.emailVerified)
      return customError(response, 'Email not Verified');

    const isPasswordMatched = await bcrypt.compare(
      data?.originalPassword,
      userExists?.auth?.password,
    );

    if (!isPasswordMatched) return customError(response, 'Invalid Password');

    if (
      data?.confirmPassword !== data?.newPassword ||
      data?.confirmPassword === ''
    )
      return customError(response, 'Invalid New Password');

    if (data?.newPassword === data?.originalPassword)
      return customError(response, 'Password Already in Use');

    const password = data?.newPassword;
    const hashedPassword = await bcrypt.hash(password, 10);

    await this.prisma.auth.update({
      where: { id: userExists?.auth?.id },
      data: { password: hashedPassword },
    });

    return customSuccess(response);
  }

  async resetPasswordEmail(email: string, response: Response): Promise<any> {
    const userExists = await findUserViaEmail(String(email), this.prisma);

    if (!userExists) return customGoneError(response, 'Email');

    if (!userExists?.auth?.emailVerified)
      return customError(response, 'Email not Verified');

    const OTP = this.generateOTP();
    const hashedOtp = await bcrypt.hash(String(OTP), 10);
    await this.prisma.auth.update({
      where: { id: userExists?.auth?.id },
      data: {
        token: null,
        isLoggedIn: false,
        otp: hashedOtp,
        otpTimeStamp: new Date(Date.now()),
        allowReset1: true,
        allowReset2: false,
      },
    });

    await this.sendEmail(String(email), OTP);
    return customSuccess(response);
  }

  async resetPasswordOtp(
    body: { email: string; otp: number },
    response: Response,
  ): Promise<any> {
    const userExists = await findUserViaEmail(String(body?.email), this.prisma);

    if (!userExists) return customGoneError(response, 'Email');

    if (!userExists?.auth?.emailVerified)
      return customError(response, 'Email not Verified');

    if (!userExists?.auth?.allowReset1)
      return customError(response, 'Reset Not Allowed');

    const otpTS = userExists?.auth?.otpTimeStamp;

    const timeDifferenceInMinutes =
      ((new Date() as any) - (otpTS as any)) / (1000 * 60);

    if (timeDifferenceInMinutes > 15) {
      await this.prisma.auth.update({
        where: { id: userExists?.auth?.id },
        data: { otp: '', allowReset1: false, allowReset2: false },
      });

      return customError(response, 'Your OTP has expired, retry');
    }

    const isOtpMatched = await bcrypt.compare(
      String(body?.otp),
      userExists?.auth?.otp,
    );

    if (isOtpMatched) {
      await this.prisma.auth.update({
        where: { id: userExists?.auth?.id },
        data: { otp: '', allowReset1: false, allowReset2: true },
      });
      return customSuccess(response);
    } else {
      return customError(response, 'Invalid OTP');
    }
  }

  async resetPassword(
    body: {
      email: string;
      newPassword: string;
      confirmPassword: string;
    },
    response: Response,
  ): Promise<any> {
    const userExists = await findUserViaEmail(String(body?.email), this.prisma);

    if (!userExists) return customGoneError(response, 'Email');
    if (!userExists?.auth?.emailVerified)
      return customError(response, 'Email not Verified');

    if (!userExists?.auth?.allowReset2)
      return customError(response, 'Reset Not Allowed');

    if (
      body?.confirmPassword !== body?.newPassword ||
      body?.confirmPassword === ''
    )
      return customError(response, 'Invalid new Passwords');

    const password = body?.newPassword;
    const hashedPassword = await bcrypt.hash(password, 10);

    await this.prisma.auth.update({
      where: { id: userExists?.auth?.id },
      data: { password: hashedPassword, allowReset2: false },
    });

    return customSuccess(response);
  }

  async resendOtp(email: string, response: Response): Promise<any> {
    const userExists = await findUserViaEmail(String(email), this.prisma);

    if (userExists?.auth?.emailVerified)
      return customError(
        response,
        'Your Email Is Already Verified, try logging in',
      );

    const OTP = this.generateOTP();
    const hashedOtp = await bcrypt.hash(String(OTP), 10);
    await this.sendEmail(email, OTP);
    await this.prisma.auth.update({
      where: { id: userExists?.auth?.id },
      data: { otp: hashedOtp, otpTimeStamp: new Date(Date.now()) },
    });

    return customSuccess(response);
  }

  async signOut(email: string, response: Response): Promise<any> {
    const userExists = await findUserViaEmail(String(email), this.prisma);

    await this.prisma.auth.update({
      where: { id: userExists?.auth?.id },
      data: { isLoggedIn: false, token: null },
    });
    response
      .clearCookie(process.env.COOKIE_ACCESS_TOKEN)
      .json({ success: 'User Signed Out Successfully' });
  }

  async verifyToken(email: string, token: string): Promise<boolean> {
    const userExists = await findUserViaEmail(String(email), this.prisma);

    if (!userExists) throw new NotFoundException('Email not found');

    if (token !== userExists?.auth?.token.toString('utf-8')) return true;
    return false;
  }
}
