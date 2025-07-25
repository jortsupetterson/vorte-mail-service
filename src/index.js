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
	 * @param {{ subject: string, plainText?: string, html?: string, headers?: Record<string,string> }} CONTENT
	 * @param {Array<string|{address:string,displayName?:string}>} RECIPIENTS
	 * @param {{ wait?: boolean, timeoutMs?: number, diag?: string }} [opts]
	 * @returns {Promise<{ id?: string, status: string, operationLocation?: string, step?: string, error?: {name:string,message:string,stack?:string,code?:any} }>}
	 */
	async sendMail(CONTENT, RECIPIENTS, opts = {}) {
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
				recipients: { to: normalizeRecipients(RECIPIENTS) },
				...(CONTENT.headers ? { headers: CONTENT.headers } : {}),
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
