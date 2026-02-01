import { Column, Entity, JoinColumn, ManyToOne } from 'typeorm';
import { Base } from './Base';
import { User } from './User';

@Entity()
export class Session extends Base {
  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column()
  userId: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  deviceName: string;

  @Column({ type: 'varchar', length: 45, nullable: true })
  ipAddress: string;

  @Column({ type: 'text', nullable: true })
  userAgent: string;

  @Column({ type: 'timestamp' })
  expiresAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastActivityAt: Date;

  @Column({ type: 'boolean', default: false })
  isRevoked: boolean;
}
