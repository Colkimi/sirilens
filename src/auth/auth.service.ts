import { Injectable, UnauthorizedException, BadRequestException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from '../users/users.service';
import { CreateUserDto, LoginDto } from '../users/dto/user.dto';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
// import { ConfigService } from '@nestjs/config';
// import axios from 'axios';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    // private configService: ConfigService,
  ) {}

  async register(createUserDto: CreateUserDto) {
    try {
      const user = await this.usersService.create(createUserDto);
      
      // Generate email verification token
      // const verificationToken = crypto.randomBytes(32).toString('hex');
      // const verificationExpires = new Date();
      // verificationExpires.setHours(verificationExpires.getHours() + 24); // 24 hours expiry
      
      // Update user with verification token
      // await this.usersService.updateVerificationToken(
      //   user.id,
      //   verificationToken,
      //   verificationExpires,
      // );
      
      // Send verification email (non-blocking)
      // const appUrl = this.configService.get<string>('APP_URL') || 'http://localhost:3000';
      // const verificationUrl = `${appUrl}/api/auth/verify-email?token=${verificationToken}`;
      
      // this.emailService.sendVerificationEmail(
      //   user.email,
      //   user.username,
      //   verificationUrl,
      // ).catch(err => {
      //   this.logger.error('Failed to send verification email:', err);
      // });
      
      return {
        message: 'Registration successful! Please check your email to verify your account.',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          isEmailVerified: false,
        },
      };
    } catch (error) {
      this.logger.error('Registration error:', error);
      throw error;
    }
  }

  async login(loginDto: LoginDto) {
    const user = await this.validateUser(loginDto.emailOrUsername, loginDto.password);
    
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if email is verified
    // if (!user.isEmailVerified) {
    //   throw new UnauthorizedException(
    //     'Please verify your email before logging in. Check your inbox for the verification link.',
    //   );
    // }

    const payload = { sub: user.id, username: user.username, role: user.role };
    
    // Check if this is the user's first login
    // const isFirstLogin = !user.lastLoginAt;
    
    // Send CTF 2026 welcome email on first login (non-blocking)
    // if (isFirstLogin) {
    //   this.emailService.sendCTF2026WelcomeEmail(user.email, user.username).catch(err => {
    //     this.logger.error('Failed to send CTF 2026 welcome email:', err);
    //   });
    // }
    
    // Update last login timestamp (non-blocking)
    this.usersService.updateLastLogin(user.id).catch(err => {
      this.logger.warn('Failed to update last login timestamp:', err);
    });
    
    // Log login activity (non-blocking)
    // this.activityService.logActivity(user.id, 'login').catch(err => {
    //   this.logger.warn('Failed to log login activity:', err);
    // });
    
    return {
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        ctfPoints: user.ctfPoints,
        isEmailVerified: user.isEmailVerified,
      },
      access_token: this.jwtService.sign(payload),
    };
  }

  async validateUser(emailOrUsername: string, password: string): Promise<any> {
    let user = await this.usersService.findByEmail(emailOrUsername);
    
    if (!user) {
      user = await this.usersService.findByUsername(emailOrUsername);
    }

    if (user && await bcrypt.compare(password, user.password)) {
      const { password, ...result } = user;
      return result;
    }
    
    return null;
  }

  // async verifyEmail(token: string) {
  //   const user = await this.usersService.findByVerificationToken(token);
    
  //   if (!user) {
  //     throw new BadRequestException('Invalid or expired verification token');
  //   }
    
  //   // Check if token has expired
  //   if (user.emailVerificationExpires && new Date() > user.emailVerificationExpires) {
  //     throw new BadRequestException('Verification token has expired. Please request a new one.');
  //   }
    
  //   // Mark email as verified
  //   await this.usersService.verifyEmail(user.id);
    
  //   // Send welcome email now that they're verified
  //   // this.emailService.sendWelcomeEmail(user.email, user.username).catch(err => {
  //   //   this.logger.error('Failed to send welcome email:', err);
  //   // });
    
  //   return {
  //     message: 'Email verified successfully! You can now log in.',
  //     user: {
  //       id: user.id,
  //       username: user.username,
  //       email: user.email,
  //       isEmailVerified: true,
  //     },
  //   };
  // }

  // async resendVerificationEmail(email: string) {
  //   const user = await this.usersService.findByEmail(email);
    
  //   if (!user) {
  //     throw new BadRequestException('User not found');
  //   }
    
  //   if (user.isEmailVerified) {
  //     throw new BadRequestException('Email is already verified');
  //   }
    
  //   // Generate new verification token
  //   const verificationToken = crypto.randomBytes(32).toString('hex');
  //   const verificationExpires = new Date();
  //   verificationExpires.setHours(verificationExpires.getHours() + 24);
    
  //   // Update user with new verification token
  //   await this.usersService.updateVerificationToken(
  //     user.id,
  //     verificationToken,
  //     verificationExpires,
  //   );
    
  //   // Send new verification email
  //   const appUrl = this.configService.get<string>('APP_URL') || 'http://localhost:3000';
  //   // const verificationUrl = `${appUrl}/api/auth/verify-email?token=${verificationToken}`;
    
  //   try {
  //     // await this.emailService.sendVerificationEmail(
  //     //   user.email,
  //     //   user.username,
  //     //   verificationUrl,
  //     // );
  //     return {
  //       message: 'Verification email sent! Please check your inbox.',
  //     };
  //   } catch (error) {
  //     this.logger.error('Failed to send verification email:', error);
  //     return {
  //       message: 'Verification token generated, but email delivery failed. Please contact support.',
  //       error: 'Email service temporarily unavailable',
  //     };
  //   }
  // }

  // async googleLogin(googleUser: any) {
  //   // Check if user exists by email
  //   let user = await this.usersService.findByEmail(googleUser.email);
    
  //   if (!user) {
  //     // Create new user from Google profile
  //     const username = googleUser.displayName.replace(/\s+/g, '').toLowerCase() + Math.floor(Math.random() * 1000);
  //     const randomPassword = Math.random().toString(36).slice(-12);
      
  //     user = await this.usersService.create({
  //       username,
  //       email: googleUser.email,
  //       password: randomPassword, // Random password (won't be used)
  //     });
      
  //     // Mark Google users as verified automatically
  //     await this.usersService.verifyEmail(user.id);
      
  //     // Send welcome email for new Google sign-ups
  //     // this.emailService.sendWelcomeEmail(user.email, user.username).catch(err => {
  //     //   this.logger.error('Failed to send welcome email:', err);
  //     // });
  //   } else if (!user.isEmailVerified) {
  //     // If user exists but not verified, verify them (Google verified their email)
  //     await this.usersService.verifyEmail(user.id);
  //   }
    
  //   const payload = { sub: user.id, username: user.username, role: user.role };
    
  //   return {
  //     user: {
  //       id: user.id,
  //       username: user.username,
  //       email: user.email,
  //       role: user.role,
  //     },
  //     access_token: this.jwtService.sign(payload),
  //   };
  // }

  // async bulkResendVerificationEmails() {
  //   const unverifiedUsers = await this.usersService.findUnverifiedUsers();
    
  //   if (unverifiedUsers.length === 0) {
  //     return {
  //       message: 'No unverified users found',
  //       sent: 0,
  //       failed: 0,
  //       details: [],
  //     };
  //   }

  //   this.logger.log(`📧 Bulk resending verification emails to ${unverifiedUsers.length} users...`);

  //   const results: Array<{ email: string; status: string; error?: string }> = [];
  //   let sentCount = 0;
  //   let failedCount = 0;

    // for (const user of unverifiedUsers) {
    //   try {
    //     // Generate new verification token
    //     const verificationToken = crypto.randomBytes(32).toString('hex');
    //     const verificationExpires = new Date();
    //     verificationExpires.setHours(verificationExpires.getHours() + 24);

    //     // Update user with verification token
    //     await this.usersService.updateVerificationToken(
    //       user.id,
    //       verificationToken,
    //       verificationExpires,
    //     );

        // Send verification email
        // const appUrl = this.configService.get<string>('APP_URL') || 'http://localhost:3000';
        // const verificationUrl = `${appUrl}/api/auth/verify-email?token=${verificationToken}`;

        // await this.emailService.sendVerificationEmail(
        //   user.email,
        //   user.username,
        //   verificationUrl,
        // );

    //     results.push({ email: user.email, status: 'sent' });
    //     sentCount++;
    //     this.logger.log(`✅ Sent verification email to ${user.email}`);
    //   } catch (error) {
    //     results.push({ email: user.email, status: 'failed', error: error.message });
    //     failedCount++;
    //     this.logger.error(`❌ Failed to send to ${user.email}:`, error.message);
    //   }

    //   // Add small delay to avoid rate limiting (100ms between emails)
    //   await new Promise(resolve => setTimeout(resolve, 100));
    // }

  //   return {
  //     message: `Verification emails sent to ${sentCount} out of ${unverifiedUsers.length} unverified users`,
  //     sent: sentCount,
  //     failed: failedCount,
  //     details: results,
  //   };
  // }

  /**
   * Frontend-handled OAuth flow: Exchange authorization code for tokens
   */
  // async exchangeGoogleCodeForTokens(code: string, redirectUri: string) {
  //   const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
  //   const clientSecret = this.configService.get<string>('GOOGLE_CLIENT_SECRET');

  //   if (!clientId || !clientSecret) {
  //     throw new BadRequestException('Google OAuth credentials not configured');
  //   }

  //   try {
  //     // Exchange authorization code for access token
  //     const response = await axios.post('https://oauth2.googleapis.com/token', {
  //       code,
  //       client_id: clientId,
  //       client_secret: clientSecret,
  //       redirect_uri: redirectUri,
  //       grant_type: 'authorization_code',
  //     });

  //     return response.data;
  //   } catch (error) {
  //     this.logger.error('Failed to exchange Google code for tokens:', error.response?.data || error.message);
  //     throw new BadRequestException('Failed to authenticate with Google');
  //   }
  // }

  /**
   * Frontend-handled OAuth flow: Verify Google token and get user info
   */
  // async verifyGoogleToken(idToken: string) {
  //   const clientId = this.configService.get<string>('GOOGLE_CLIENT_ID');
    
  //   if (!clientId) {
  //     throw new BadRequestException('Google OAuth client ID not configured');
  //   }

  //   const client = new OAuth2Client(clientId);

  //   try {
  //     const ticket = await client.verifyIdToken({
  //       idToken,
  //       audience: clientId,
  //     });

  //     const payload = ticket.getPayload();
      
  //     if (!payload || !payload.email) {
  //       throw new BadRequestException('Invalid Google token - no email provided');
  //     }

  //     return {
  //       email: payload.email,
  //       displayName: payload.name || payload.email.split('@')[0],
  //       googleId: payload.sub,
  //       emailVerified: payload.email_verified,
  //     };
  //   } catch (error) {
  //     this.logger.error('Failed to verify Google token:', error.message);
  //     throw new BadRequestException('Invalid Google token');
  //   }
  // }

  /**
   * Frontend-handled OAuth flow: Complete Google authentication
   */
  // async googleVerifyAndLogin(code: string, redirectUri: string) {
  //   // Exchange code for tokens
  //   const tokens = await this.exchangeGoogleCodeForTokens(code, redirectUri);
    
  //   if (!tokens.id_token) {
  //     throw new BadRequestException('No ID token received from Google');
  //   }

  //   // Verify token and get user info
  //   const googleUser = await this.verifyGoogleToken(tokens.id_token);

  //   // Find or create user
  //   let user = await this.usersService.findByEmail(googleUser.email);
    
  //   if (!user) {
  //     // Create new user from Google profile
  //     const username = googleUser.displayName.replace(/\s+/g, '').toLowerCase() + Math.floor(Math.random() * 1000);
  //     const randomPassword = Math.random().toString(36).slice(-12);
      
  //     user = await this.usersService.create({
  //       username,
  //       email: googleUser.email,
  //       password: randomPassword, // Random password (won't be used)
  //     });
      
  //     // Mark Google users as verified automatically
  //     await this.usersService.verifyEmail(user.id);
      
  //     // Send welcome email for new Google sign-ups
  //     this.emailService.sendWelcomeEmail(user.email, user.username).catch(err => {
  //       this.logger.error('Failed to send welcome email:', err);
  //     });
  //   } else if (!user.isEmailVerified) {
  //     // If user exists but not verified, verify them (Google verified their email)
  //     await this.usersService.verifyEmail(user.id);
  //   }
    
  //   const payload = { sub: user.id, username: user.username, role: user.role };
    
  //   // Check if this is the user's first login
  //   const isFirstLogin = !user.lastLoginAt;
    
  //   // Send CTF 2026 welcome email on first login (non-blocking)
  //   if (isFirstLogin) {
  //     this.emailService.sendCTF2026WelcomeEmail(user.email, user.username).catch(err => {
  //       this.logger.error('Failed to send CTF 2026 welcome email:', err);
  //     });
  //   }
    
  //   // Update last login timestamp (non-blocking)
  //   this.usersService.updateLastLogin(user.id).catch(err => {
  //     this.logger.warn('Failed to update last login timestamp:', err);
  //   });
    
  //   // Log login activity (non-blocking)
  //   this.activityService.logActivity(user.id, 'login').catch(err => {
  //     this.logger.warn('Failed to log login activity:', err);
  //   });
    
  //   return {
  //     user: {
  //       id: user.id,
  //       username: user.username,
  //       email: user.email,
  //       role: user.role,
  //       ctfPoints: user.ctfPoints,
  //       isEmailVerified: user.isEmailVerified,
  //     },
  //     access_token: this.jwtService.sign(payload),
  //   };
  // }
}
