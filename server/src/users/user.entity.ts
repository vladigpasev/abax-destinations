import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  @Exclude()
  password: string;

  @Column()
  role: string;

  @Column({ default: false })
  emailConfirmed: boolean;

  // Поле за съхранение на токен за смяна на парола
  @Column({ nullable: true })
  resetPasswordToken?: string;

  // Поле за съхранение на времето на изтичане на токена за смяна на парола
  @Column({ type: 'timestamp', nullable: true })
  resetPasswordTokenExpiry?: Date;

  // Add approval status for users with roles that require admin or office approval
  @Column({ default: true }) // Default to true for roles that don't require approval
  approved: boolean;

  @CreateDateColumn()
  createdAt: Date;
}
