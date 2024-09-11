import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Group } from './group.entity';
import { Logger } from '@nestjs/common';

@Injectable()
export class GroupsService {
  private readonly logger = new Logger(GroupsService.name);

  constructor(
    @InjectRepository(Group)
    private groupsRepository: Repository<Group>,
  ) {}

  async createGroup(groupData: Partial<Group>): Promise<Group> {
    try {
      return await this.groupsRepository.save(groupData);
    } catch (error) {
      this.logger.error('Error creating group', error.stack);
      throw new HttpException('Error creating group', HttpStatus.BAD_REQUEST);
    }
  }

  async getGroups(): Promise<Group[]> {
    return this.groupsRepository.find();
  }
}
