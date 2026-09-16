import { Injectable, NotFoundException, ConflictException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './entities/user.entity';
import { CreateUserDto, UpdateUserDto } from './dto/user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const existingUser = await this.usersRepository.findOne({
      where: [
        { email: createUserDto.email },
        { username: createUserDto.username },
      ],
    });

    if (existingUser) {
      throw new ConflictException('User with this email or username already exists');
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const user = this.usersRepository.create({
    username: createUserDto.username,
    email: createUserDto.email,
    password: hashedPassword,
    role: UserRole.USER,
    });

    return this.usersRepository.save(user);
  }

async findAll(): Promise<Omit<User, 'password'>[]> {
  const users = await this.usersRepository.find();

  return users.map(({ password, ...safeUser }) => safeUser);
}

  async findOne(id: string): Promise<Omit<User, 'password'>> {
    const user = await this.usersRepository.findOne({ 
      where: { id }
    });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
  const { password, ...safeUser } = user;
  return safeUser;
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { email } });
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { username } });
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<Omit<User, 'password'>> {
    const user = await this.findOne(id);
    Object.assign(user, updateUserDto);
    const updated = await this.usersRepository.save(user);
    
    const { password, ...safeUser } = updated;
    // Log profile update activity (non-blocking)
    
    return safeUser;
  }

  async updateLastLogin(id: string): Promise<void> {
    await this.usersRepository.update(id, { lastLoginAt: new Date() });
  }

  async remove(id: string): Promise<void> {
    const user = await this.findOne(id);
    
    this.logger.log(`🗑️ Deleting user ${user.username} (${id}) and all related data...`);
    
    // Use a transaction to ensure all deletes succeed or fail together
    await this.usersRepository.manager.transaction(async (manager) => {

      // Finally, delete the user
      await manager.query(
        'DELETE FROM users WHERE id = $1',
        [id]
      );
      this.logger.log(`✅ Successfully deleted user ${user.username} and all related data`);
    });
  }

  // async findByVerificationToken(token: string): Promise<User | null> {
  //   return this.usersRepository.findOne({
  //     where: { emailVerificationToken: token },
  //   });
  // }

  // async updateVerificationToken(
  //   userId: string,
  //   token: string,
  //   expires: Date,
  // ): Promise<void> {
  //   await this.usersRepository.update(userId, {
  //     emailVerificationToken: token,
  //     emailVerificationExpires: expires,
  //   });
  // }

  // async verifyEmail(userId: string): Promise<void> {
  //   await this.usersRepository.update(userId, {
  //     isEmailVerified: true,
  //     emailVerificationToken: null,
  //     emailVerificationExpires: null,
  //   });
  // }

  // async findUnverifiedUsers(): Promise<User[]> {
  //   return this.usersRepository.find({
  //     where: { isEmailVerified: false },
  //     order: { createdAt: 'DESC' },
  //   });
  // }
}
