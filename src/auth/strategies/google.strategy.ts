// import { Injectable } from '@nestjs/common';
// import { PassportStrategy } from '@nestjs/passport';
// import { ConfigService } from '@nestjs/config';

// @Injectable()
// export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
//   constructor(private configService: ConfigService) {
//     super({
//       clientID: configService.get<string>('GOOGLE_CLIENT_ID') || '',
//       clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET') || '',
//       callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL') || '',
//       scope: ['email', 'profile'],
//       passReqToCallback: true, // Enable passing request to callback
//     });
//   }

//   async validate(
//     request: any,
//     accessToken: string,
//     refreshToken: string,
//     profile: any,
//     done: VerifyCallback,
//   ): Promise<any> {
//     const { id, name, emails, photos } = profile;
    
//     // Extract the state parameter which contains the redirect URL
//     const state = request.query.state;
    
//     const user = {
//       googleId: id,
//       email: emails[0].value,
//       firstName: name.givenName,
//       lastName: name.familyName,
//       displayName: name.givenName + ' ' + name.familyName,
//       picture: photos[0].value,
//       accessToken,
//       redirectUrl: state || null, // Store redirect URL from state
//     };
    
//     done(null, user);
//   }
// }
