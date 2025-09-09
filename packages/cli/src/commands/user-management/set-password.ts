import { Command } from '@n8n/decorators';
import { Container } from '@n8n/di';
import { z } from 'zod';

import { BaseCommand } from '../base-command';
import { PasswordUtility } from '@/services/password.utility';
import { UserRepository } from '@n8n/db';
import { UserError } from 'n8n-workflow';

const flagsSchema = z.object({
	email: z.string().describe('Email of the user whose password you want to set'),
	password: z
		.string()
		.min(8, 'Password must be at least 8 characters long')
		.describe('New password to set for the user'),
});

@Command({
	name: 'user-management:set-password',
	description:
		'Set a new password for a user without requiring the old password (for forgotten passwords).',
	examples: [
		"--email='owner@example.com' --password='newStrongP@ssw0rd'",
	],
	flagsSchema,
})
export class SetPasswordCommand extends BaseCommand<z.infer<typeof flagsSchema>> {
	async run(): Promise<void> {
		const { email, password } = this.flags;

		if (!email || !password) {
			throw new UserError('Both --email and --password flags are required.');
		}

		const userRepository = Container.get(UserRepository);
		const passwordUtility = Container.get(PasswordUtility);

		// Emails are stored lowercased
		const normalizedEmail = email.toLowerCase();
		const user = await userRepository.findOne({ where: { email: normalizedEmail }, relations: ['role'] });

		if (!user) {
			throw new UserError(`User with email ${normalizedEmail} not found.`);
		}

		const hashed = await passwordUtility.hash(password);
		user.password = hashed;

		await userRepository.save(user);

		this.logger.info(`Password successfully updated for ${normalizedEmail}.`);
	}

	async catch(error: Error): Promise<void> {
		this.logger.error('Error setting user password. See log messages for details.');
		this.logger.error(error.message);
		process.exit(1);
	}
}
