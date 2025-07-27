/**
 * MailServiceClientSDK
 * --------------------
 * Thin, IntelliSense‑friendly wrapper for the underlying mailer. The first
 * parameter is always the Cloudflare **env** object; following parameters mirror
 * the core implementation so editors surface required/optional fields cleanly.
 *
 * Usage:
 * ```js
 * import { sendEmail } from "./mail-client.js";
 *
 * export default {
 *   async fetch(req, env) {
 *     const res = await sendEmail(
 *       env,
 *       ["alice@example.com"],
 *       { subject: "Hello", plainText: "Hi there!" },
 *       false,                         // omit attachments
 *       false,                         // omit headers
 *       { wait: true, timeoutMs: 20_000 }
 *     );
 *     return Response.json(res);
 *   }
 * }
 * ```
 *
 * > This wrapper forwards the call to `env.MAIL_SERVICE.sendEmail(...)`.
 * > It also accepts `false` as a sentinel to explicitly omit optional parameters.
 *
 * @module MailServiceClientSDK
 */

/* ---------------------------------- Types --------------------------------- */

/**
 * Cloudflare Worker environment bindings for the client wrapper.
 * `MAIL_SERVICE` is a Service/DO binding exposing `sendEmail(...)`.
 * @typedef {object} MailEnv
 * @property {{ sendEmail(
 *   recipients: Recipient[],
 *   content: EmailContent,
 *   attachments?: AcsEmailAttachment[] | undefined,
 *   headers?: Record<string,string> | undefined,
 *   opts?: SendOptions | undefined
 * ): Promise<SendResult> }} MAIL_SERVICE
 *
 * @typedef {string | { address: string, displayName?: string }} Recipient
 *
 * @typedef EmailContent
 * @property {string} subject
 * @property {string} [plainText]
 * @property {string} [html]
 *
 * @typedef AcsEmailAttachment
 * @property {string} [name]
 * @property {string} [contentType]
 * @property {string} [contentInBase64]
 * @property {any}    [data]
 *
 * @typedef SendOptions
 * @property {boolean} [wait=false]
 * @property {number}  [timeoutMs=30000]
 * @property {"entered"|"validated"|"secrets"|"key"|"signed"|`post:${number}`} [diag]
 *
 * @typedef SendError
 * @property {string} name
 * @property {string} message
 * @property {string} [stack]
 * @property {any}    [code]
 *
 * @typedef SendResult
 * @property {"Diag"|"Running"|"Succeeded"|"Failed"|"Error"} status
 * @property {string} [id]
 * @property {string} [operationLocation]
 * @property {string} [step]
 * @property {SendError} [error]
 */

/* --------------------------------- API ------------------------------------ */

/**
 * Sends an email via the MAIL_SERVICE binding.
 *
 * Optional parameters may be passed as `undefined` or `false` (the latter is
 * treated as “omit”). The function performs light validation to give immediate,
 * actionable errors at the edge before crossing service boundaries.
 *
 * @param {MailEnv} env
 * @param {Recipient[]} recipients
 * @param {EmailContent} content
 * @param {AcsEmailAttachment[]|false} [attachments]
 * @param {Record<string,string>|false} [headers]
 * @param {SendOptions|false} [opts]
 * @returns {Promise<SendResult>}
 */
export async function sendEmail(env, recipients, content, attachments, headers, opts) {
	// Basic guardrails for quick feedback and better DX.
	if (!env || !env.MAIL_SERVICE || typeof env.MAIL_SERVICE.sendEmail !== 'function') {
		throw new TypeError('env.MAIL_SERVICE.sendEmail is not available.');
	}
	if (!Array.isArray(recipients) || recipients.length === 0) {
		throw new TypeError('recipients must be a non-empty array.');
	}
	if (!content || typeof content.subject !== 'string' || content.subject.length === 0) {
		throw new TypeError('content.subject is required (string).');
	}

	const ATTACHMENTS = attachments === false ? undefined : attachments;
	const HEADERS = headers === false ? undefined : headers;
	const OPTS = opts === false ? undefined : opts;

	return env.MAIL_SERVICE.sendEmail(
		/** @type {Recipient[]} */ (recipients),
		/** @type {EmailContent} */ (content),
		/** @type {AcsEmailAttachment[]|undefined} */ (ATTACHMENTS),
		/** @type {Record<string,string>|undefined} */ (HEADERS),
		/** @type {SendOptions|undefined} */ (OPTS)
	);
}
