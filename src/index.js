import { WorkerEntrypoint } from 'cloudflare:workers';

const SENDER_ADDRESS = 'DoNotReply@mail.vorte.app';
const API_VERSION = '2023-03-31';
const MAX_ATTEMPTS = 4;
const BASE_BACKOFF_MS = 500;
const MAX_BODY_SIZE = 10 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 5000;

const encoder = new TextEncoder();

export class VorteMailService extends WorkerEntrypoint {
	/** @type {CryptoKey|null} */ _hmacKey = null;
	/** @type {string|null}    */ _emptyBodyHash = null;

	async _getHmacKey(secretB64) {
		if (this._hmacKey) return this._hmacKey;
		const keyBytes = base64Decode(secretB64.trim());
		this._hmacKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
		return this._hmacKey;
	}

	async _getEmptyBodyHash() {
		if (this._emptyBodyHash) return this._emptyBodyHash;
		const h = await crypto.subtle.digest('SHA-256', new Uint8Array());
		this._emptyBodyHash = base64Encode(new Uint8Array(h));
		return this._emptyBodyHash;
	}

	/**
	 * Sends an email via **Azure Communication Services – Email**.
	 *
	 * Builds an HMAC‑SHA256 signed request (signed headers: `x-ms-date;host;x-ms-content-sha256`)
	 * and uses idempotency headers (`Operation-Id`, `Repeatability-*`). A `202 Accepted` means the
	 * operation is running on the service. With `wait=true`, the function polls the operation until
	 * completion or until `timeoutMs` elapses. Responses `429` and `5xx` are retried with quadratic
	 * backoff; `409` triggers polling of the existing operation.
	 *
	 * Validates essentials (subject, body size) and aborts the network request after `FETCH_TIMEOUT_MS`.
	 * Payload size is limited by `MAX_BODY_SIZE`.
	 *
	 * > **Diagnostics:** Set `opts.diag` to any documented step (see `SendDiagStep`) to return early
	 * with `{ status: "Diag", step }`. This enables fast unit testing and fault isolation without
	 * making an outbound call.
	 *
	 * @async
	 *
	 * @param {Recipient[]} RECIPIENTS
	 * Recipients. A string value is coerced to `{ address: "<email>" }`. Object form may include
	 * `displayName`. Duplicates and formats are normalized by `normalizeRecipients`.
	 *
	 * @param {EmailContent} CONTENT
	 * Message content. `subject` is required. At least one of `plainText` or `html` should be supplied.
	 *
	 * @param {Array<Record<string, any>>} [ATTACHMENTS]
	 * Attachments passed through to ACS Email as-is. The function does not transform their shape.
	 *
	 * @param {Record<string, string>} [HEADERS]
	 * Additional headers to include under the `headers` field of the ACS request payload.
	 *
	 * @param {SendOptions} [opts]
	 * Execution and diagnostics options.
	 *
	 * @returns {Promise<SendResult>}
	 * Returns the operation identifier and status. On errors the shape is
	 * `{ status: "Error", error }`. On success at minimum `{ status: "Running" | "Succeeded" | "Failed" }`.
	 *
	 * @typedef {string | { address: string, displayName?: string }} Recipient
	 *
	 * @typedef EmailContent
	 * @property {string} subject            Email subject. **Required.**
	 * @property {string} [plainText]        Plain‑text body.
	 * @property {string} [html]             HTML body.
	 *
	 * @typedef SendOptions
	 * @property {boolean} [wait=false]      If true, poll the operation until completion or timeout.
	 * @property {number}  [timeoutMs=30000] Max time in milliseconds to wait when `wait=true`.
	 * @property {SendDiagStep} [diag]       Return early at the given diagnostic step without I/O.
	 *
	 * @typedef {"entered"|"validated"|"secrets"|"key"|"signed"|`post:${number}`} SendDiagStep
	 * Diagnostic steps:
	 * - `"entered"`: function entry.
	 * - `"validated"`: payload validated and size within limits.
	 * - `"secrets"`: endpoint and access key fetched from environment.
	 * - `"key"`: HMAC key material derived.
	 * - `"signed"`: request signed, before network I/O.
	 * - ``"post:<status>"``: POST completed; `<status>` is the HTTP status code.
	 *
	 * @typedef SendError
	 * @property {string} name
	 * @property {string} message
	 * @property {string} [stack]
	 * @property {any}    [code]
	 *
	 * @typedef SendResult
	 * @property {"Diag"|"Running"|"Succeeded"|"Failed"|"Error"} status
	 * @property {string} [id]                    Operation id. Falls back to local `operationId` if not returned.
	 * @property {string} [operationLocation]     ACS `Operation-Location`, when available.
	 * @property {string} [step]                  Diagnostic step when `status === "Diag"`.
	 * @property {SendError} [error]              Error payload when `status === "Error"`.
	 *
	 * @notes
	 * - Uses external constants: `SENDER_ADDRESS`, `API_VERSION`, `MAX_BODY_SIZE`, `MAX_ATTEMPTS`,
	 *   `BASE_BACKOFF_MS`, and `FETCH_TIMEOUT_MS`.
	 * - Requires secrets in environment bindings: `AZURE_COMMUNICATIONS_ENDPOINT`, `AZURE_COMMUNICATIONS_SECRET`.
	 * - Host header uses the **hostname only** (no port) per ACS HMAC rules.
	 */
	async sendEmail(RECIPIENTS, CONTENT, ATTACHMENTS, HEADERS, opts = {}) {
		const { wait = false, timeoutMs = 30000, diag } = opts;

		try {
			if (diag === 'entered') return { status: 'Diag', step: 'entered' };

			// Validate
			if (!CONTENT?.subject || typeof CONTENT.subject !== 'string') {
				throw new Error('CONTENT.subject is required');
			}
			const bodyObj = {
				senderAddress: SENDER_ADDRESS,
				content: {
					subject: CONTENT.subject,
					...(CONTENT.plainText ? { plainText: CONTENT.plainText } : {}),
					...(CONTENT.html ? { html: CONTENT.html } : {}),
				},
				...(ATTACHMENTS ? { attachments: ATTACHMENTS } : {}),
				recipients: { to: normalizeRecipients(RECIPIENTS) },
				replyTo: [{ address: 'support@vorte.app', displayName: 'Vorte Support' }],
				...(HEADERS ? { headers: HEADERS } : {}),
				userEngagementTrackingDisabled: true,
			};
			const bodyStr = JSON.stringify(bodyObj);
			if (bodyStr.length > MAX_BODY_SIZE) throw new Error(`Payload too large: ${bodyStr.length} bytes`);
			if (diag === 'validated') return { status: 'Diag', step: 'validated' };

			// Secrets / endpoint
			const [endpoint, accessKeyB64] = await Promise.all([
				this.env.AZURE_COMMUNICATIONS_ENDPOINT.get(),
				this.env.AZURE_COMMUNICATIONS_SECRET.get(),
			]);
			if (!endpoint) throw new Error('AZURE_COMMUNICATIONS_ENDPOINT missing');
			if (!accessKeyB64) throw new Error('AZURE_COMMUNICATIONS_SECRET missing');
			if (diag === 'secrets') return { status: 'Diag', step: 'secrets' };

			const endpointUrl = new URL(endpoint);
			const sendUrl = new URL('/emails:send', endpointUrl);
			sendUrl.searchParams.set('api-version', API_VERSION);

			// HMAC: host = hostname (ei porttia)
			const host = endpointUrl.hostname;

			const operationId = crypto.randomUUID();
			const clientReqId = crypto.randomUUID();
			const firstSent = new Date().toUTCString();
			const key = await this._getHmacKey(accessKeyB64);
			if (diag === 'key') return { status: 'Diag', step: 'key' };

			let lastErrorText = '';
			for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
				const dateHdr = new Date().toUTCString();
				const contentHash = await sha256Base64(bodyStr);
				const stringToSign = `POST\n${sendUrl.pathname}${sendUrl.search}\n${dateHdr};${host};${contentHash}`;
				const sigBytes = await crypto.subtle.sign('HMAC', key, encoder.encode(stringToSign));
				const signature = base64Encode(new Uint8Array(sigBytes));
				const authHeader = `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`;

				if (diag === 'signed') return { status: 'Diag', step: 'signed' };

				const controller = new AbortController();
				const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
				const res = await fetch(sendUrl.toString(), {
					method: 'POST',
					headers: {
						Authorization: authHeader,
						'Content-Type': 'application/json',
						'x-ms-date': dateHdr,
						'x-ms-content-sha256': contentHash,
						'x-ms-client-request-id': clientReqId,
						'Operation-Id': operationId,
						'Repeatability-Request-Id': operationId,
						'Repeatability-First-Sent': firstSent,
					},
					body: bodyStr,
					signal: controller.signal,
				}).catch((err) => ({ ok: false, status: 0, statusText: String(err), headers: new Headers() }));
				clearTimeout(timer);

				if (diag === 'post') return { status: 'Diag', step: `post:${res.status}` };

				if (res.ok && res.status === 202) {
					const opLoc = res.headers.get('Operation-Location') || undefined;
					if (!wait || !opLoc) {
						const stub = await res.json().catch(() => ({}));
						return { id: stub.id ?? operationId, status: stub.status || 'Running', operationLocation: opLoc };
					}
					const poll = await this._waitForResult(opLoc, host, key, timeoutMs);
					return { id: poll.id ?? operationId, status: poll.status, operationLocation: opLoc };
				}

				if (res.status === 409) {
					const opLoc = res.headers.get('Operation-Location');
					if (opLoc) {
						const poll = await this._waitForResult(opLoc, host, key, timeoutMs);
						return { id: poll.id ?? operationId, status: poll.status, operationLocation: opLoc };
					}
				}

				if (res.status === 429) {
					const ra = Number(res.headers.get('retry-after')) || 2;
					await sleep(ra * 1000 + Math.random() * 100);
					continue;
				}

				if (res.status === 0 || res.status >= 500) {
					const delay = BASE_BACKOFF_MS * (attempt + 1) ** 2 + Math.random() * 100;
					await sleep(delay);
					lastErrorText = await safeText(res);
					continue;
				}

				lastErrorText = await safeText(res);
				return {
					status: 'Error',
					error: { name: 'HTTPError', message: `ACS ${res.status} ${res.statusText}: ${lastErrorText}`, code: res.status },
				};
			}

			return { status: 'Error', error: { name: 'RetryError', message: `ACS send failed after retries: ${lastErrorText || 'no detail'}` } };
		} catch (e) {
			const err = normalizeError(e);
			return { status: 'Error', error: err };
		}
	}

	async _waitForResult(operationLocation, host, key, timeoutMs) {
		const deadline = Date.now() + timeoutMs;
		let retryAfter = 2;
		const emptyHash = await this._getEmptyBodyHash();

		while (true) {
			const dateHdr = new Date().toUTCString();
			const urlObj = new URL(operationLocation);
			const pathAndQuery = urlObj.pathname + urlObj.search;
			const stringToSign = `GET\n${pathAndQuery}\n${dateHdr};${host};${emptyHash}`;
			const sigBytes = await crypto.subtle.sign('HMAC', key, encoder.encode(stringToSign));
			const signature = base64Encode(new Uint8Array(sigBytes));
			const authHeader = `HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature=${signature}`;

			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
			const res = await fetch(operationLocation, {
				method: 'GET',
				headers: {
					Authorization: authHeader,
					'x-ms-date': dateHdr,
					'x-ms-content-sha256': emptyHash,
				},
				signal: controller.signal,
			});
			clearTimeout(timer);

			const json = await res.json().catch(() => ({}));
			if (json.status && !['NotStarted', 'Running'].includes(json.status)) return json;

			const ra = Number(res.headers.get('retry-after')) || retryAfter;
			await sleep(Math.min(ra, 10) * 1000 + Math.random() * 50);
			retryAfter = Math.min(retryAfter * 1.5, 10);
			if (Date.now() > deadline) return { status: 'Running', id: json.id };
		}
	}
}

// -------- Helpers --------

function normalizeRecipients(list) {
	return list.map((r) => {
		const addr = typeof r === 'string' ? r : r.address;
		if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(addr)) throw new Error(`Invalid email address: ${addr}`);
		return typeof r === 'string' ? { address: addr } : { address: addr, displayName: r.displayName };
	});
}

async function safeText(res) {
	try {
		return await res.text();
	} catch {
		return '';
	}
}
function sleep(ms) {
	return new Promise((r) => setTimeout(r, ms));
}
async function sha256Base64(str) {
	const data = new TextEncoder().encode(str);
	const hash = await crypto.subtle.digest('SHA-256', data);
	return base64Encode(new Uint8Array(hash));
}
function base64Encode(bytes) {
	let s = '';
	for (let b of bytes) s += String.fromCharCode(b);
	return btoa(s);
}
function base64Decode(b64) {
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

// --- Vaadittu handler deploihin (404 + hard-cache) ---
export default {
	async fetch(request, env, ctx) {
		const res = new Response('Not Found', {
			status: 404,
			headers: { 'Cache-Control': 'public, max-age=31536000, immutable' },
		});
		ctx.waitUntil(
			(async () => {
				try {
					await caches.default.put(request, res.clone());
				} catch {}
			})()
		);
		return res;
	},
};
