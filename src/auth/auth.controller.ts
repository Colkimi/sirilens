import { Controller, Post, Body, HttpCode, HttpStatus, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
// import { AuthGuard } from '@nestjs/passport';
// import { ConfigService } from '@nestjs/config';
// import type { Response } from 'express';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginDto } from '../users/dto/user.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    // private readonly configService: ConfigService,
  ) {}

  @Post('register')
  @ApiOperation({ 
    summary: 'Register a new user',
    description: 'Create a new user account.',
  })
  @ApiResponse({ 
    status: 201, 
    description: 'User successfully registered. .',
    schema: {
      example: {
        message: 'Registration successful! Please check your email to verify your account.',
        user: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          username: 'johndoe',
          email: 'john@example.com',
          role: 'user',
          isEmailVerified: false,
        },
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Invalid input or user already exists' })
  register(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  @ApiOperation({ 
    summary: 'Login user',
    description: 'Authenticate with email/username and password. Email must be verified to login.',
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Login successful',
    schema: {
      example: {
        user: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          username: 'johndoe',
          email: 'john@example.com',
          role: 'user',
          isEmailVerified: true,
        },
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Invalid credentials or email not verified' })
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  // @Get('verify-email')
  // @ApiOperation({ 
  //   summary: 'Verify email address',
  //   description: 'Verify user email using the token sent to their email.',
  // })
  // @ApiQuery({ name: 'token', description: 'Email verification token', required: true })
  // @ApiQuery({ name: 'redirect', description: 'Frontend URL to redirect to after verification', required: false })
  // @ApiResponse({ 
  //   status: 200, 
  //   description: 'Email verified successfully',
  //   schema: {
  //     example: {
  //       message: 'Email verified successfully! You can now log in.',
  //       user: {
  //         id: '123e4567-e89b-12d3-a456-426614174000',
  //         username: 'johndoe',
  //         email: 'john@example.com',
  //         isEmailVerified: true,
  //       },
  //     },
  //   },
  // })
  // @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  // async verifyEmail(
  //   @Query('token') token: string,
  //   @Query('redirect') redirectUrl: string,
  //   @Res() res: Response,
  // ) {
  //   // const result = await this.authService.verifyEmail(token);
    
  //   // Determine which frontend to redirect to
  //   // Priority: redirect param > COMPETITION_FRONTEND_URL > CTF_FRONTEND_URL > default
  //   const competitionUrl = this.configService.get<string>('COMPETITION_FRONTEND_URL');
  //   const practiceUrl = this.configService.get<string>('CTF_FRONTEND_URL') || 'https://ctf.geniushackers.guru';
  //   const defaultUrl = competitionUrl || practiceUrl;
  //   const frontendUrl = redirectUrl || defaultUrl;
    
  //   return res.redirect(`${frontendUrl}/login?verified=true`);
  // }

  // @Post('resend-verification')
  // @HttpCode(HttpStatus.OK)
  // @ApiOperation({ 
  //   summary: 'Resend verification email',
  //   description: 'Request a new verification email if the previous one expired.',
  // })
  // @ApiBody({ 
  //   schema: { 
  //     type: 'object', 
  //     properties: { 
  //       email: { type: 'string', example: 'john@example.com' } 
  //     } 
  //   } 
  // })
  // @ApiResponse({ 
  //   status: 200, 
  //   description: 'Verification email sent',
  //   schema: {
  //     example: {
  //       message: 'Verification email sent! Please check your inbox.',
  //     },
  //   },
  // })
  // @ApiResponse({ status: 400, description: 'User not found or email already verified' })
  // async resendVerification(@Body('email') email: string) {
  //   return this.authService.resendVerificationEmail(email);
  // }

  // @Post('admin/resend-all-verifications')
  // @HttpCode(HttpStatus.OK)
  // @ApiOperation({ 
  //   summary: 'Bulk resend verification emails (Admin)',
  //   description: 'Resend verification emails to all unverified users. Use this to help users who registered when emails were failing.',
  // })
  // @ApiResponse({ 
  //   status: 200, 
  //   description: 'Bulk resend completed',
  //   schema: {
  //     example: {
  //       message: 'Verification emails sent to 15 unverified users',
  //       sent: 15,
  //       failed: 0,
  //       details: [
  //         { email: 'user1@example.com', status: 'sent' },
  //         { email: 'user2@example.com', status: 'sent' },
  //       ],
  //     },
  //   },
  // })
  // async bulkResendVerifications() {
  //   return this.authService.bulkResendVerificationEmails();
  // }

  // @Get('google/url')
  // @ApiOperation({ 
  //   summary: 'Get Google OAuth URL',
  //   description: 'Returns the Google OAuth URL for frontend to redirect to. Use this to initiate OAuth from frontend. Pass "redirect" query param to specify where to redirect after auth.',
  // })
  // @ApiQuery({ 
  //   name: 'redirect', 
  //   description: 'Frontend URL to redirect to after authentication (e.g., competition or practice site)', 
  //   required: false,
  //   example: 'https://hackfest.geniushackers.guru'
  // })
  // @ApiResponse({ 
  //   status: 200, 
  //   description: 'Google OAuth URL',
  //   schema: {
  //     example: {
  //       url: 'https://accounts.google.com/o/oauth2/v2/auth?...',
  //     },
  //   },
  // })
  // getGoogleAuthUrl(@Query('redirect') redirectUrl?: string) {
  //   const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID') || '';
  //   const callbackUrl = this.configService.get<string>('GOOGLE_CALLBACK_URL') || '';
  //   const scope = encodeURIComponent('email profile');
    
  //   // Use the provided redirect URL or default
  //   const competitionUrl = this.configService.get<string>('COMPETITION_FRONTEND_URL');
  //   const practiceUrl = this.configService.get<string>('CTF_FRONTEND_URL') || 'https://ctf.geniushackers.guru';
  //   const defaultRedirect = competitionUrl || practiceUrl;
  //   const finalRedirect = redirectUrl || defaultRedirect;
    
  //   // Encode the redirect URL as the state parameter
  //   const state = encodeURIComponent(finalRedirect);
    
  //   const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(callbackUrl)}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${state}`;
    
  //   return { url: googleAuthUrl };
  // }

  // @Get('google')
  // @UseGuards(AuthGuard('google'))
  // @ApiOperation({ 
  //   summary: 'Sign in with Google (Direct)',
  //   description: 'Initiates Google OAuth 2.0 authentication flow. Redirects to Google sign-in page. Use /auth/google/url endpoint for frontend-initiated flow.',
  // })
  // @ApiQuery({ 
  //   name: 'redirect', 
  //   description: 'Frontend URL to redirect to after authentication', 
  //   required: false 
  // })
  // @ApiResponse({ status: 302, description: 'Redirects to Google OAuth page' })
  // async googleAuth(@Query('redirect') redirectUrl?: string) {
  //   // Store redirect URL in state parameter (handled by guard)
  // }

  // @Get('google/callback')
  // @UseGuards(AuthGuard('google'))
  // @ApiOperation({ 
  //   summary: 'Google OAuth callback',
  //   description: 'Handles Google OAuth callback. Returns JWT token or redirects to frontend with token.',
  // })
  // @ApiResponse({ status: 200, description: 'Google sign-in successful' })
  // async googleAuthCallback(@Req() req, @Res() res: Response) {
  //   const result = await this.authService.googleLogin(req.user);
    
  //   // Get redirect URL from user object (set by strategy from state parameter) or use default
  //   const competitionUrl = this.configService.get<string>('COMPETITION_FRONTEND_URL');
  //   const practiceUrl = this.configService.get<string>('CTF_FRONTEND_URL') || 'https://ctf.geniushackers.guru';
  //   const defaultUrl = competitionUrl || practiceUrl;
  //   const redirectUrl = req.user.redirectUrl || defaultUrl;
    
  //   // Redirect to the appropriate frontend with token
  //   return res.redirect(`${redirectUrl}/auth/callback?token=${result.access_token}`);
  // }

  // @Post('google/verify')
  // @HttpCode(HttpStatus.OK)
  // @ApiOperation({ 
  //   summary: 'Verify Google OAuth code (Frontend-handled flow)',
  //   description: 'Exchange Google authorization code for JWT token. Use this when frontend handles the OAuth redirect. Frontend receives the code from Google, sends it here for verification, and receives a JWT token.',
  // })
  // @ApiBody({ 
  //   schema: { 
  //     type: 'object', 
  //     properties: { 
  //       code: { 
  //         type: 'string', 
  //         description: 'Authorization code from Google OAuth redirect',
  //         example: '4/0AfJohXmY...'
  //       },
  //       redirectUri: { 
  //         type: 'string', 
  //         description: 'The redirect URI used in the OAuth flow (must match what was sent to Google)',
  //         example: 'https://ctf.geniushackers.guru/auth/callback'
  //       }
  //     },
  //     required: ['code', 'redirectUri']
  //   } 
  // })
  // @ApiResponse({ 
  //   status: 200, 
  //   description: 'Google authentication successful, JWT token returned',
  //   schema: {
  //     example: {
  //       user: {
  //         id: '123e4567-e89b-12d3-a456-426614174000',
  //         username: 'johndoe',
  //         email: 'john@example.com',
  //         role: 'user',
  //         ctfPoints: 0,
  //         isEmailVerified: true,
  //       },
  //       access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  //     },
  //   },
  // })
  // @ApiResponse({ status: 400, description: 'Invalid authorization code or redirect URI' })
  // async googleVerify(
  //   @Body('code') code: string,
  //   @Body('redirectUri') redirectUri: string,
  // ) {
  //   if (!code || !redirectUri) {
  //     throw new BadRequestException('Both code and redirectUri are required');
  //   }

  //   return this.authService.googleVerifyAndLogin(code, redirectUri);
  // }
}
