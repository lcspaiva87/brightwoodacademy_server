import { IsEmail, IsString, IsOptional, IsEnum } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  password: string;

  @IsString()
  name: string;

  @IsEnum(['user', 'admin'])
  @IsOptional()
  role?: string = 'user';
}
