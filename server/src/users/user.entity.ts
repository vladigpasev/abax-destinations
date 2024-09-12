import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude()  // Exclude password when serializing
  password: string;

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
  @Exclude()  // Exclude refresh token from responses
  refreshToken?: string;  // Store refresh token securely

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;  // Track last updates
}
