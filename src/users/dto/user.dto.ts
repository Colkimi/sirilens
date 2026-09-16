import { IsEmail, IsString, MinLength, IsOptional } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {

  @ApiProperty({
    description: 'Unique username for the account',
    example: 'johndoe',
    minLength: 3,
  })
  @IsString()
  @MinLength(3)
  username: string = '';

  @ApiProperty({
    description: 'User email address',
    example: 'john@example.com',
  })
  @IsEmail()
  email: string = '';

  @ApiProperty({
    description: 'Strong password (minimum 8 characters)',
    example: 'SecurePass123!',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  password: string = '';
}

export class UpdateUserDto {
  @ApiProperty({
    description: 'Unique username for the account',
    example: 'johndoe',
    minLength: 3,
  })
  @IsOptional()
  @IsString()
  @MinLength(3)
  username?: string;

}

export class LoginDto {
  @ApiProperty({
    description: 'Email address or username',
    example: 'john@example.com',
  })
  @IsString()
  emailOrUsername: string = '';

  @ApiProperty({
    description: 'Account password',
    example: 'SecurePass123!',
  })
  @IsString()
  password: string = '';
}
