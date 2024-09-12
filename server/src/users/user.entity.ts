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
  id: number; // Keep auto-increment id (no longer used for operations)

  @Column({ unique: true })
  uuid: string; // Use UUID for operations instead of id

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude() // Exclude password when serializing
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
  @Exclude() // Exclude refresh token from responses
  refreshToken?: string; // Store refresh token securely

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date; // Track last updates

  @Column({ default: 0 })
  refreshTokenVersion: number; // Track token version

  @BeforeInsert()
  generateUuid() {
    this.uuid = uuidv4(); // Automatically generate UUID when a new user is created
  }
}
