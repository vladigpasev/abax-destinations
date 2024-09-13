import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Brackets, Repository } from 'typeorm';
import { User } from './user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private usersRepository: Repository<User>,
  ) {}

  async findByEmail(email: string): Promise<User> {
    return this.usersRepository.findOneBy({ email });
  }

  async findByPhone(phone: string): Promise<User> {
    return this.usersRepository.findOneBy({ phone });
  }
  

  async findByUuid(uuid: string): Promise<User> {
    return this.usersRepository.findOneBy({ uuid });
  }

  async create(user: User): Promise<User> {
    return this.usersRepository.save(user);
  }

  async findByRefreshToken(refreshToken: string): Promise<User | undefined> {
    return this.usersRepository.findOne({ where: { refreshToken } });
  }

  async update(uuid: string, updateUserDto: Partial<User>): Promise<User> {
    await this.usersRepository.update({ uuid }, updateUserDto);
    return this.findByUuid(uuid);
  }

  async findByResetPasswordToken(token: string): Promise<User | undefined> {
    return this.usersRepository.findOne({
      where: { resetPasswordToken: token },
    });
  }

  async getAllUsersByRole(role: string): Promise<User[]> {
    return this.usersRepository.find({ where: { role } });
  }

  async getAllUsers(): Promise<User[]> {
    return this.usersRepository.find();
  }

  async getUsersByRoleAndAccess(
    role: string,
    currentUser: User,
  ): Promise<User[]> {
    const queryBuilder = this.usersRepository.createQueryBuilder('user');

    // Admin can access all users
    if (currentUser.role === 'admin') {
      return queryBuilder.getMany();
    }

    // Office can access guide and tourist roles, and their own user
    if (currentUser.role === 'office') {
      return queryBuilder
        .where(
          'user.role = :guide OR user.role = :tourist OR user.uuid = :userUuid',
          {
            guide: 'guide',
            tourist: 'tourist',
            userUuid: currentUser.uuid,
          },
        )
        .getMany();
    }

    // Guide can only access their own user
    if (currentUser.role === 'guide') {
      return queryBuilder
        .where('user.uuid = :userUuid', { userUuid: currentUser.uuid })
        .getMany();
    }

    // Tourist can only access their own user
    if (currentUser.role === 'tourist') {
      return queryBuilder
        .where('user.uuid = :userUuid', { userUuid: currentUser.uuid })
        .getMany();
    }

    return [];
  }

  async updateUserByRoleAndAccess(
    uuid: string,
    updateUserDto: Partial<User>,
    currentUser: User,
  ): Promise<User> {
    const existingUser = await this.findByUuid(uuid);

    if (!existingUser) {
      throw new Error('User not found');
    }

    // 1. Remove restricted fields
    const restrictedFields = [
      'email',
      'password',
      'resetPasswordToken',
      'resetPasswordTokenExpiry',
      'emailConfirmed',
    ];
    this.removeRestrictedFields(updateUserDto, restrictedFields);

    // 2. Prevent role change for own account
    if (this.isAttemptingToChangeOwnRole(currentUser, uuid, updateUserDto)) {
      throw new Error('You are not allowed to change your own role');
    }

    // 3. Role change handling
    if (updateUserDto.role) {
      this.handleRoleChange(currentUser, existingUser, updateUserDto);
    }

    // 4. Guide and tourist profile update (self-update only)
    if (this.isSelfUpdating(currentUser, existingUser)) {
      await this.usersRepository.update({ uuid }, updateUserDto);
      return this.findByUuid(uuid);
    }

    // 5. Admin and office update logic
    if (this.isAdminOrOffice(currentUser)) {
      await this.usersRepository.update({ uuid }, updateUserDto);
      return this.findByUuid(uuid);
    }

    // 6. No permission to update
    throw new Error('Not allowed to update this user');
  }

  // Helper methods for cleaner logic

  private removeRestrictedFields(
    updateUserDto: Partial<User>,
    restrictedFields: string[],
  ): void {
    restrictedFields.forEach((field) => {
      if (updateUserDto[field] !== undefined) {
        console.log(`Field ${field} is restricted and will be ignored.`);
        delete updateUserDto[field];
      }
    });
  }

  private isAttemptingToChangeOwnRole(
    currentUser: User,
    uuid: string,
    updateUserDto: Partial<User>,
  ): boolean {
    return (
      currentUser.uuid === uuid &&
      updateUserDto.role &&
      updateUserDto.role !== currentUser.role
    );
  }

  private handleRoleChange(
    currentUser: User,
    existingUser: User,
    updateUserDto: Partial<User>,
  ): void {
    if (
      currentUser.role === 'admin' &&
      currentUser.uuid !== existingUser.uuid
    ) {
      console.log('Admin is changing role.');
    } else if (currentUser.role === 'office') {
      if (
        ['tourist', 'guide'].includes(existingUser.role) &&
        ['tourist', 'guide'].includes(updateUserDto.role)
      ) {
        console.log('Office is changing role between tourist and guide.');
      } else {
        throw new Error(
          'Office can only change roles between tourist and guide',
        );
      }
    } else {
      throw new Error('You are not allowed to change roles');
    }
  }

  private isSelfUpdating(currentUser: User, existingUser: User): boolean {
    return (
      ['guide', 'tourist'].includes(currentUser.role) &&
      currentUser.uuid === existingUser.uuid
    );
  }

  private isAdminOrOffice(currentUser: User): boolean {
    return ['admin', 'office'].includes(currentUser.role);
  }

  async getUsersByFiltersAndSorting(
    currentUser: User,
    role?: string,
    sortByEmail?: 'asc' | 'desc',
    sortByCreatedAt?: 'asc' | 'desc',
  ): Promise<User[]> {
    const queryBuilder = this.usersRepository.createQueryBuilder('user');

    // Dynamic where conditions based on role
    if (currentUser.role === 'admin') {
      // Admin can access all users
    } else if (currentUser.role === 'office') {
      queryBuilder.where(
        new Brackets((qb) => {
          qb.where('user.role IN (:...roles)', {
            roles: ['guide', 'tourist'],
          }).orWhere('user.uuid = :userUuid', { userUuid: currentUser.uuid });
        }),
      );
    } else {
      queryBuilder.where('user.uuid = :userUuid', {
        userUuid: currentUser.uuid,
      });
    }

    // Apply role filter
    if (role) {
      queryBuilder.andWhere('user.role = :role', { role });
    }

    // Apply sorting by email
    if (sortByEmail) {
      queryBuilder.addOrderBy(
        'user.email',
        sortByEmail === 'asc' ? 'ASC' : 'DESC',
      );
    }

    // Apply sorting by createdAt
    if (sortByCreatedAt) {
      queryBuilder.addOrderBy(
        'user.createdAt',
        sortByCreatedAt === 'asc' ? 'ASC' : 'DESC',
      );
    }

    return queryBuilder.getMany();
  }
}
