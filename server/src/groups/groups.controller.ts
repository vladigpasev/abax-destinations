import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { GroupsService } from './groups.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { Roles } from '../auth/roles.decorator';
import { RolesGuard } from '../auth/roles.guard';

@Controller('groups')
@UseGuards(JwtAuthGuard, RolesGuard)
export class GroupsController {
  constructor(private readonly groupsService: GroupsService) {}

  @Post()
  @Roles('admin', 'office')
  async createGroup(@Body() createGroupDto: any) {
    return this.groupsService.createGroup(createGroupDto);
  }

  @Get()
  async getGroups() {
    return this.groupsService.getGroups();
  }
}
