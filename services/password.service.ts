import { ServiceSchema } from "../../../lib/types";

import DBMixin from "moleculer-db";
import SqlAdapter from "moleculer-db-adapter-sequelize";
import Sequelize from "sequelize";

import _ from "lodash";
import bcrypt from "bcryptjs";

(DBMixin as any).actions = {};
const Service: ServiceSchema = {
	name: "password",
	version: "api.v1",

	/**
	 * Mixins
	 */
	mixins: [DBMixin],

	adapter: new SqlAdapter(process.env.DATABASE_URL || "sqlite://:memory:"),

	model: {
		name: "password",
		define: {
			user: {
				type: Sequelize.INTEGER,
			},
			password: {
				type: Sequelize.STRING,
			},
			createdBy: {
				type: Sequelize.STRING,
			},
			deleted: {
				type: Sequelize.BOOLEAN,
				default: false,
			},
			deletedAt: {
				type: Sequelize.DATE,
				default: null,
			},
		},
	},

	/**
	 * Service settings
	 */
	settings: {},

	/**
	 * Service dependencies
	 */
	// dependencies: [],

	/**
	 * Actions
	 */
	actions: {
		save: {
			rest: "POST /save",
			params: {
				user: { type: "number", min: 1, integer: true, positive: true },
				password: { type: "string", min: 6, max: 255 },
			},
			async handler(ctx) {
				try {
					const { user, password } = ctx.params;
					const createdBy = ctx.meta.creator.trim().toLowerCase();

					// compare all passwords
					const [result] = await this.adapter.db.query(
						`SELECT password FROM passwords WHERE user = '${user}' AND createdBy = '${createdBy}'`
					);

					for (let item of result) {
						const oldPassword = item.password;

						if (bcrypt.compareSync(password, oldPassword)) {
							return {
								code: 400,
								i18n: "PASSWORD_EXISTS",
							};
						}
					}

					// update deleted: false to deleted: true and deletedAt
					await this.adapter.db.query(`
						UPDATE passwords SET deleted = '1', deletedAt = datetime('now') WHERE user = '${user}' AND deleted ='0' AND createdBy = '${createdBy}'
					`);

					const newPassword = bcrypt.hashSync(password, 10);

					await this.adapter.insert({
						user,
						password: newPassword,
						createdBy: ctx.meta.creator.trim().toLowerCase(),
						deleted: false,
						deletedAt: null,
					});

					return {
						code: 200,
						i18n: "PASSWORD_SAVED",
					};
				} catch (error) {
					console.error(error);

					return {
						code: 500,
					};
				}
			},
		},
		compare: {
			rest: "POST /compare",
			params: {
				user: {
					type: "number",
					min: 1,
					integer: true,
					positive: true,
				},
				password: { type: "string", min: 6, max: 255 },
			},
			async handler(ctx) {
				try {
					const { user, password } = ctx.params;
					const createdBy = ctx.meta.creator.trim().toLowerCase();

					// find user that its password does not deleted
					const [result] = await this.adapter.db.query(
						`SELECT * FROM passwords WHERE user = '${user}' AND deleted = '0' AND createdBy = '${createdBy}'`
					);

					if (result.length == 0) {
						return {
							code: 400,
							i18n: "PASSWORD_NOT_FOUND",
						};
					}

					const hashedPassword = result[0]["password"];

					const compare = bcrypt.compareSync(password, hashedPassword);

					return {
						code: compare ? 200 : 400,
						i18n: compare ? "PASSWORD_IS_SAME" : "PASSWORD_IS_NOT_SAME",
					};
				} catch (error) {
					return {
						code: 500,
					};
				}
			},
		},
		deleteById: {
			rest: "DELETE /delete/:id",
			params: {
				id: {
					type: "number",
					min: 1,
					integer: true,
					positive: true,
					convert: true,
				},
				force: {
					type: "boolean",
					optional: true,
					default: false,
				},
			},
			async handler(ctx) {
				try {
					const { id, force } = ctx.params;
					const createdBy = ctx.meta.creator.trim().toLowerCase();

					if (force) {
						await this.adapter.db.query(
							`DELETE FROM passwords WHERE id = '${id}' AND createdBy = '${createdBy}'`
						);
					} else {
						await this.adapter.db.query(
							`UPDATE passwords SET deleted = '1' AND deletedAt = NOW() WHERE id = '${id}' AND createdBy = '${createdBy}'`
						);
					}

					return {
						code: 200,
						i18n: "PASSWORD_DELETED",
					};
				} catch (error) {
					return {
						code: 500,
					};
				}
			},
		},
		getAllByUser: {
			rest: "GET /user/:user",
			params: {
				user: {
					type: "number",
					convert: true,
					min: 1,
					integer: true,
					positive: true,
				},
			},
			async handler(ctx) {
				try {
					const { user } = ctx.params;
					const createdBy = ctx.meta.creator.trim().toLowerCase();

					const [result] = await this.adapter.db.query(
						`SELECT * FROM passwords WHERE user = '${user}' AND createdBy = '${createdBy}'`
					);

					return {
						code: 200,
						i18n: "ALL_PASSWORDS",
						meta: {
							page: 1,
							last: 1,
							limit: result.length,
							total: result.length,
						},
						data: result,
					};
				} catch (error) {
					return {
						code: 500,
					};
				}
			},
		},
		getAll: {
			rest: "GET /",
			async handler(ctx) {
				try {
					const createdBy = ctx.meta.creator.trim().toLowerCase();

					const [result] = await this.adapter.db.query(
						`SELECT * FROM passwords WHERE deleted = '0' AND createdBy = '${createdBy}'`
					);

					return {
						code: 200,
						i18n: "ALL_PASSWORDS",
						meta: {
							page: 1,
							last: 1,
							limit: result.length,
							total: result.length,
						},
						data: result,
					};
				} catch (error) {
					return {
						code: 500,
					};
				}
			},
		},
	},

	/**
	 * Events
	 */
	events: {},

	/**
	 * Methods
	 */
	methods: {},

	/**
	 * Service created lifecycle event handler
	 */
	// created() {},

	/**
	 * Service started lifecycle event handler
	 */
	// started() { },

	/**
	 * Service stopped lifecycle event handler
	 */
	// stopped() { }
};

export = Service;
