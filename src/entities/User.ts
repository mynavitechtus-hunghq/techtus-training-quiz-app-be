import { Column, Entity } from 'typeorm';

import { Base } from './Base';

@Entity()
export class User extends Base {
  @Column({ unique: true, nullable: false })
  email: string;

  @Column({ select: false, nullable: false })
  password: string;
}
