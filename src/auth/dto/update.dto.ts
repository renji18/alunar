import { IsNotEmpty, IsString } from 'class-validator';

export class UpdatePsswordDto {
  @IsNotEmpty()
  @IsString()
  readonly originalPassword: string;

  @IsNotEmpty()
  @IsString()
  readonly newPassword: string;

  @IsNotEmpty()
  @IsString()
  readonly confirmPassword: string;
}
