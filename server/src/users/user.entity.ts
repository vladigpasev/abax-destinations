import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  BeforeInsert,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { v4 as uuidv4 } from 'uuid';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  uuid: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column()
  firstName: string; // New field for first name

  @Column()
  lastName: string; // New field for last name

  @Column({ unique: true })
  phone: string; // New field for phone number

  @Column()
  role: string;

  @Column({ default: false })
  emailConfirmed: boolean;

  @Column({ nullable: true })
  resetPasswordToken?: string;

  @Column({ type: 'timestamp', nullable: true })
  resetPasswordTokenExpiry?: Date;

  @Column({ default: true })
  approved: boolean;

  @Column({ nullable: true })
  @Exclude()
  refreshToken?: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ default: 0 })
  refreshTokenVersion: number;

  @BeforeInsert()
  generateUuid() {
    this.uuid = uuidv4();
  }
}
