import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Group {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column({ unique: true })
  joinCode: string;

  @Column()
  departureDate: Date;

  @Column()
  returnDate: Date;

  @Column({ default: false })
  deleted: boolean;
}
