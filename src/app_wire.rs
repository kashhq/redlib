//! What the Android app's requests look like on the wire: each request type's headers, in the
//! order the app's HTTP stacks add them, its signed analytics session (`x-reddit-session`) and
//! its GraphQL body. The builders are pure over the install, the token and the request's facts;
//! `apply` puts a list on a request so names, order and case go out as listed (wreq's
//! `OrigHeaderMap`). Used by `oauth_device` (the mint), `client` (REST reads, GraphQL) and
//! `media_proxy`. The install itself is `app_install`; the two transports are `transport`.
//!
//! Ported from Averyy/wafer (Apache-2.0), `wafer/_reddit_app.py` (`token_request`,
//! `read_headers`, `gql_headers`, `RedditAppAnalyticsSession`) and
//! https://github.com/Averyy/wafer/blob/main/docs/ref-reddit.md, whose header orders come from
//! the decompiled interceptors of release 2026.44.0 and Chromium 143's `//net`.

use crate::app_install::Install;
use base64::{
	engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
	Engine as _,
};
use log::info;
use serde::Serialize;
use serde_json::Value;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wreq::header::OrigHeaderMap;
use wreq::RequestBuilder;

/// A request's headers, in the order they go on the wire.
pub(crate) type Headers = Vec<(&'static str, String)>;

/// The official Android app's OAuth client id (public; shipped in every install).
const CLIENT_ID: &str = "ohXpoqrZYub1kg";

/// The mint's body, compact as the app's JSON writer sends it.
pub(crate) const MINT_BODY: &str = r#"{"scopes":["*","email","pii","adsread","adsedit"]}"#;

// OkHttp (mint, REST, media) asks for gzip only; Cronet 143 (GraphQL) for gzip and deflate (the
// app builds it without brotli, and Cronet 143 leaves zstd off).
const OKHTTP_ACCEPT_ENCODING: &str = "gzip";
const CRONET_ACCEPT_ENCODING: &str = "gzip, deflate";
/// The HTTP/2 priority Cronet adds at its default (MEDIUM) request priority.
const CRONET_PRIORITY: &str = "u=1, i";
const ACCEPT_LANGUAGE: &str = "en-US";
const GQL_ACCEPT: &str = "application/graphql-response+json, application/json";
const GQL_CONTENT_TYPE: &str = "application/json; charset=utf-8";
const MINT_CONTENT_TYPE: &str = "application/json; charset=UTF-8";
/// The app's GraphQL client makes up to this many attempts per operation.
const GQL_MAX_ATTEMPTS: u8 = 3;
/// The device class the app reports for a current flagship.
const DEVICE_TIER: &str = "v2t1";
/// `X-Reddit-Http-QoS` classes by their floor in Mbps, highest first.
const QUALITY_CLASSES: [(f64, &str); 4] = [(20.0, "EXCELLENT"), (10.0, "GOOD"), (5.0, "STANDARD"), (2.0, "LIMITED")];

/// The quarantine and gated-subreddit opt-in. The app sends no Cookie; redlib adds this one only
/// for a reader who opted in, where OkHttp's BridgeInterceptor would put a cookie: last.
const QUARANTINE_COOKIE: &str = "_options=%7B%22pref_quarantine_optin%22%3A%20true%2C%20%22pref_gated_sr_optin%22%3A%20true%7D";

// The app signs its analytics session with HMAC-SHA512 under a key every install ships (public,
// like the client id): base64 G0mP32i4zFWsTD3pY1Dj/ydl5yYF9aWyzPvnBflr/PU=
const SESSION_SECRET: [u8; 32] = [
	0x1b, 0x49, 0x8f, 0xdf, 0x68, 0xb8, 0xcc, 0x55, 0xac, 0x4c, 0x3d, 0xe9, 0x63, 0x50, 0xe3, 0xff, 0x27, 0x65, 0xe7, 0x26, 0x05, 0xf5, 0xa5, 0xb2, 0xcc, 0xfb, 0xe7, 0x05,
	0xf9, 0x6b, 0xfc, 0xf5,
];
const SESSION_KEY_TAG: &str = "1ab1c15bb9f3183b5aea60ba9f1e12bde3fa4cc0960a80567455f7e106f123b1";
/// A session idle this long is replaced, as the app starts one on returning to the foreground.
const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);

/// What every API request's headers are built from: the install, this process's analytics session
/// and this request's bandwidth sample.
pub(crate) struct Ctx<'a> {
	pub(crate) install: &'a Install,
	pub(crate) session: String,
	pub(crate) mbps: f64,
}

impl<'a> Ctx<'a> {
	/// The context of a request about to be sent: it counts as activity for the session.
	pub(crate) fn live(install: &'a Install) -> Self {
		Self {
			install,
			session: session_header(),
			mbps: install.sample_down_rate(),
		}
	}
}

/// What the app's shared client adds to every request: the network class and estimate, the
/// device class, compression and the phone's hardware video decoders.
fn network(ctx: &Ctx) -> [(&'static str, String); 5] {
	[
		("X-Reddit-Http-QoS", quality(ctx.mbps).to_string()),
		("X-Reddit-Device-Tier", DEVICE_TIER.to_string()),
		("x-reddit-compression", "1".to_string()),
		("X-Reddit-QoS", format!("down-rate-mbps={:.3}", ctx.mbps)),
		("X-Reddit-Media-Codecs", format!("available-codecs={}", ctx.install.phone.codecs.join(", "))),
	]
}

/// What the app adds to an API request after `Authorization`.
fn identity(install: &Install) -> [(&'static str, String); 7] {
	let phone = install.phone;
	[
		("Client-Vendor-ID", install.device_id.clone()),
		("x-reddit-device-id", install.device_id.clone()),
		("User-Agent", install.user_agent()),
		("X-Dev-Ad-Id", install.ad_id.clone()),
		("Device-Name", format!("{};{}", phone.manufacturer, phone.model)),
		("x-reddit-dpr", java_float(phone.density)),
		// Java's (int) (widthPixels / density): truncated.
		("x-reddit-width", ((phone.width_px as f32 / phone.density) as u32).to_string()),
	]
}

/// The loid (once the install has one), the session and the persisted device id, in that order.
fn session_tail(ctx: &Ctx) -> Headers {
	let mut headers = Vec::with_capacity(3);
	if !ctx.install.loid.is_empty() {
		headers.push(("x-reddit-loid", ctx.install.loid.clone()));
	}
	headers.push(("x-reddit-session", ctx.session.clone()));
	headers.push(("X-Reddit-P-Device-ID", ctx.install.p_device_id.clone()));
	headers
}

/// The anonymous token mint, as the app's auth client (OkHttp) sends it. OkHttp's
/// BridgeInterceptor adds the last three; `MINT_BODY` is the body.
pub(crate) fn mint_headers(ctx: &Ctx) -> Headers {
	let [qos_class, tier, compression, qos, codecs] = network(ctx);
	let mut headers: Headers = vec![("Authorization", format!("Basic {}", STANDARD.encode(format!("{CLIENT_ID}:"))))];
	if !ctx.install.loid.is_empty() {
		headers.push(("x-reddit-loid", ctx.install.loid.clone()));
	}
	headers.extend([
		qos_class,
		tier,
		("User-Agent", ctx.install.user_agent()),
		compression,
		qos,
		codecs,
		("Client-Vendor-ID", ctx.install.device_id.clone()),
		("X-Reddit-P-Device-ID", ctx.install.p_device_id.clone()),
		("x-reddit-session", ctx.session.clone()),
		("Content-Type", MINT_CONTENT_TYPE.to_string()),
		("Content-Length", MINT_BODY.len().to_string()),
		("Accept-Encoding", OKHTTP_ACCEPT_ENCODING.to_string()),
	]);
	headers
}

/// A REST read (GET or HEAD), as the app's REST client (OkHttp) sends it, plus the opt-in cookie
/// when `quarantine`.
pub(crate) fn read_headers(ctx: &Ctx, token: &str, quarantine: bool) -> Headers {
	let mut headers: Headers = network(ctx).into();
	headers.push(("Authorization", format!("Bearer {token}")));
	headers.extend(identity(ctx.install));
	headers.extend(session_tail(ctx));
	headers.push(("Accept-Language", ACCEPT_LANGUAGE.to_string()));
	headers.push(("Accept-Encoding", OKHTTP_ACCEPT_ENCODING.to_string()));
	if quarantine {
		headers.push(("Cookie", QUARANTINE_COOKIE.to_string()));
	}
	headers
}

/// A GraphQL POST, as the app's Apollo client sends it over Cronet: the app's headers between the
/// `content-length` Chromium's `//net` sets first and the encoding and priority it adds last.
/// `attempt` counts this operation's resends (0 for the first send).
pub(crate) fn gql_headers(ctx: &Ctx, token: &str, payload: &GqlPayload, attempt: u8) -> Headers {
	let mut headers: Headers = vec![
		("Content-Length", payload.json.len().to_string()),
		("X-Reddit-Retry", format!("attempt={attempt}, max={GQL_MAX_ATTEMPTS}")),
	];
	if let Some(name) = &payload.operation_name {
		headers.push(("X-APOLLO-OPERATION-NAME", name.clone()));
	}
	if let Some(id) = &payload.operation_id {
		headers.push(("X-APOLLO-OPERATION-ID", id.clone()));
	}
	headers.push(("accept", GQL_ACCEPT.to_string()));
	headers.extend(network(ctx));
	headers.push(("Authorization", format!("Bearer {token}")));
	headers.push(("Accept-Language", ACCEPT_LANGUAGE.to_string()));
	headers.extend(identity(ctx.install));
	headers.extend(session_tail(ctx));
	headers.extend([
		("Content-Type", GQL_CONTENT_TYPE.to_string()),
		("Accept-Encoding", CRONET_ACCEPT_ENCODING.to_string()),
		("priority", CRONET_PRIORITY.to_string()),
	]);
	headers
}

/// A media fetch from Reddit's CDN: the install's User-Agent and the reader's forwarded
/// conditional and range headers. No x-reddit-* headers: the app's image loader is assumed not
/// to add its API headers (unverified; wafer covers API requests only). `Accept: */*` keeps
/// Reddit from redirecting an image to its /media landing page.
pub(crate) fn media_headers(user_agent: String, forwarded: Headers) -> Headers {
	let mut headers: Headers = vec![("User-Agent", user_agent), ("Accept", "*/*".to_string())];
	headers.extend(forwarded);
	// OkHttp's BridgeInterceptor asks for gzip only when the request has no Range (a compressed
	// body cannot be sliced by byte offset). wreq follows the same rule, so it adds nothing here.
	if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("range")) {
		headers.push(("Accept-Encoding", OKHTTP_ACCEPT_ENCODING.to_string()));
	}
	headers
}

/// `builder` with `headers` set, sent in their order and case. A request whose headers carry
/// every name wreq would add (Accept-Encoding, Content-Length) gets nothing added on top: the
/// transports set no default headers. Before this the headers were shuffled per request
/// (upstream #324); no real app shuffles, so the fork sends one order (docs/fork.md).
pub(crate) fn apply(mut builder: RequestBuilder, headers: Headers) -> RequestBuilder {
	let mut order = OrigHeaderMap::with_capacity(headers.len());
	for (name, value) in headers {
		order.insert(name);
		builder = builder.header(name, value);
	}
	builder.orig_headers(order)
}

/// A GraphQL body as sent, with the operation headers read from it.
pub(crate) struct GqlPayload {
	pub(crate) json: String,
	operation_name: Option<String>,
	operation_id: Option<String>,
}

/// The wire form of a `gql_ops::body`: compact, keys in the order the app's Apollo writer emits
/// them (serde_json's map would sort them), the operation headers' values alongside. A name or
/// hash that is not a plain identifier is left out of the headers.
pub(crate) fn gql_payload(body: &Value) -> serde_json::Result<GqlPayload> {
	let persisted = &body["extensions"]["persistedQuery"];
	let wire = Envelope {
		operation_name: &body["operationName"],
		variables: &body["variables"],
		extensions: Extensions {
			persisted_query: PersistedQuery {
				version: &persisted["version"],
				sha256_hash: &persisted["sha256Hash"],
			},
		},
	};
	Ok(GqlPayload {
		json: serde_json::to_string(&wire)?,
		operation_name: header_token(&body["operationName"]),
		operation_id: header_token(&persisted["sha256Hash"]),
	})
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope<'a> {
	operation_name: &'a Value,
	variables: &'a Value,
	extensions: Extensions<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Extensions<'a> {
	persisted_query: PersistedQuery<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PersistedQuery<'a> {
	version: &'a Value,
	sha256_hash: &'a Value,
}

fn header_token(value: &Value) -> Option<String> {
	value
		.as_str()
		.filter(|s| (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
		.map(str::to_string)
}

fn quality(mbps: f64) -> &'static str {
	QUALITY_CLASSES.iter().find(|(floor, _)| mbps >= *floor).map_or("VERY_LIMITED", |(_, name)| name)
}

/// A float as Java's `String.valueOf(float)` prints it in the range densities take: `2.625`,
/// `3.0` (never Rust's bare `3`).
fn java_float(value: f32) -> String {
	let text = value.to_string();
	if text.contains('.') {
		text
	} else {
		format!("{text}.0")
	}
}

/// `x-reddit-session` for the session `session_id` started at `created_ms` (unix ms):
/// `<id>.2.<created ms>.<key tag>-<unpadded base64url HMAC-SHA512 of everything before the '-'>`.
fn sign_session(session_id: &str, created_ms: u128) -> String {
	let payload = format!("{session_id}.2.{created_ms}.{SESSION_KEY_TAG}");
	// BoringSSL's HMAC fails only on allocation failure.
	let mac = boring2::hash::hmac_sha512(&SESSION_SECRET, payload.as_bytes()).expect("HMAC-SHA512 over a fixed key");
	format!("{payload}-{}", URL_SAFE_NO_PAD.encode(mac))
}

/// The process's analytics session: one per process start, replaced after `SESSION_IDLE` without
/// a Reddit API request. Holds the signed header, which is fixed for the session's life.
struct Session {
	header: String,
	last_request: Instant,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

/// The session header for a request sent now, starting a session when there is none or it idled.
fn session_header() -> String {
	let mut slot = SESSION.lock().unwrap_or_else(PoisonError::into_inner);
	header_at(&mut slot, Instant::now(), new_session)
}

/// `slot`'s header for a request at `now`, replacing an idle or missing session with `start()`.
fn header_at(slot: &mut Option<Session>, now: Instant, start: impl FnOnce() -> String) -> String {
	match slot {
		Some(session) if now.duration_since(session.last_request) < SESSION_IDLE => {
			session.last_request = now;
			session.header.clone()
		}
		_ => {
			info!("[📊] new analytics session ({})", if slot.is_some() { "the last one idled" } else { "process start" });
			let header = start();
			*slot = Some(Session {
				header: header.clone(),
				last_request: now,
			});
			header
		}
	}
}

fn new_session() -> String {
	let id: String = std::iter::repeat_with(fastrand::alphanumeric).take(18).collect();
	let created_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_millis());
	sign_session(&id, created_ms)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::app_install::tests::fixed;
	use serde_json::json;

	const TEST_SESSION: &str = "sess";

	fn ctx(install: &Install, mbps: f64) -> Ctx<'_> {
		Ctx {
			install,
			session: TEST_SESSION.to_string(),
			mbps,
		}
	}

	fn names(headers: &Headers) -> Vec<&'static str> {
		headers.iter().map(|(name, _)| *name).collect()
	}

	fn value<'a>(headers: &'a Headers, name: &str) -> &'a str {
		headers.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str()).unwrap_or_else(|| panic!("no {name}"))
	}

	const NETWORK: [&str; 5] = ["X-Reddit-Http-QoS", "X-Reddit-Device-Tier", "x-reddit-compression", "X-Reddit-QoS", "X-Reddit-Media-Codecs"];
	const IDENTITY: [&str; 7] = [
		"Client-Vendor-ID",
		"x-reddit-device-id",
		"User-Agent",
		"X-Dev-Ad-Id",
		"Device-Name",
		"x-reddit-dpr",
		"x-reddit-width",
	];

	#[test]
	fn the_mint_is_sent_in_the_auth_clients_order() {
		let first = fixed();
		assert_eq!(
			names(&mint_headers(&ctx(&first, 42.0))),
			[
				"Authorization",
				"X-Reddit-Http-QoS",
				"X-Reddit-Device-Tier",
				"User-Agent",
				"x-reddit-compression",
				"X-Reddit-QoS",
				"X-Reddit-Media-Codecs",
				"Client-Vendor-ID",
				"X-Reddit-P-Device-ID",
				"x-reddit-session",
				"Content-Type",
				"Content-Length",
				"Accept-Encoding",
			]
		);
		let renewal = fixed().with_loid(Some("t2_loid".to_string()));
		let headers = mint_headers(&ctx(&renewal, 42.0));
		assert_eq!(&names(&headers)[..3], ["Authorization", "x-reddit-loid", "X-Reddit-Http-QoS"]);
		assert_eq!(value(&headers, "Authorization"), "Basic b2hYcG9xclpZdWIxa2c6");
		assert_eq!(value(&headers, "x-reddit-loid"), "t2_loid");
		assert_eq!(value(&headers, "Content-Type"), "application/json; charset=UTF-8");
		assert_eq!(value(&headers, "Content-Length"), "50");
		assert_eq!(MINT_BODY.len(), 50);
		assert_eq!(value(&headers, "Accept-Encoding"), "gzip");
	}

	#[test]
	fn a_rest_read_is_sent_in_the_rest_clients_order() {
		let install = fixed().with_loid(Some("t2_loid".to_string()));
		let headers = read_headers(&ctx(&install, 42.0), "tok", false);
		let expected: Vec<&str> = NETWORK
			.into_iter()
			.chain(["Authorization"])
			.chain(IDENTITY)
			.chain(["x-reddit-loid", "x-reddit-session", "X-Reddit-P-Device-ID", "Accept-Language", "Accept-Encoding"])
			.collect();
		assert_eq!(names(&headers), expected);
		assert_eq!(value(&headers, "Authorization"), "Bearer tok");
		assert_eq!(value(&headers, "Accept-Language"), "en-US");
		assert_eq!(value(&headers, "Accept-Encoding"), "gzip");
		assert!(!names(&headers).contains(&"Cookie"), "the app sends no Cookie");
		assert!(!names(&headers).contains(&"Host"), "wreq derives the authority from the URL");
	}

	#[test]
	fn a_quarantine_opt_in_adds_the_cookie_last_and_a_fresh_install_no_loid() {
		let install = fixed();
		let headers = read_headers(&ctx(&install, 42.0), "tok", true);
		assert_eq!(names(&headers).last(), Some(&"Cookie"));
		assert!(value(&headers, "Cookie").starts_with("_options="));
		assert!(!names(&headers).contains(&"x-reddit-loid"));
	}

	#[test]
	fn a_graphql_post_is_sent_in_cronets_order() {
		let install = fixed().with_loid(Some("t2_loid".to_string()));
		let body = json!({
			"operationName": "PostComments",
			"variables": { "id": "t3_abc" },
			"extensions": { "persistedQuery": { "version": 1, "sha256Hash": "abc123" } },
		});
		let payload = gql_payload(&body).unwrap();
		let headers = gql_headers(&ctx(&install, 42.0), "tok", &payload, 1);
		let expected: Vec<&str> = ["Content-Length", "X-Reddit-Retry", "X-APOLLO-OPERATION-NAME", "X-APOLLO-OPERATION-ID", "accept"]
			.into_iter()
			.chain(NETWORK)
			.chain(["Authorization", "Accept-Language"])
			.chain(IDENTITY)
			.chain(["x-reddit-loid", "x-reddit-session", "X-Reddit-P-Device-ID", "Content-Type", "Accept-Encoding", "priority"])
			.collect();
		assert_eq!(names(&headers), expected);
		assert_eq!(value(&headers, "Content-Length"), payload.json.len().to_string());
		assert_eq!(value(&headers, "X-Reddit-Retry"), "attempt=1, max=3");
		assert_eq!(value(&headers, "X-APOLLO-OPERATION-NAME"), "PostComments");
		assert_eq!(value(&headers, "X-APOLLO-OPERATION-ID"), "abc123");
		assert_eq!(value(&headers, "accept"), "application/graphql-response+json, application/json");
		assert_eq!(value(&headers, "Content-Type"), "application/json; charset=utf-8");
		assert_eq!(value(&headers, "Accept-Encoding"), "gzip, deflate");
		assert_eq!(value(&headers, "priority"), "u=1, i");
	}

	#[test]
	fn the_graphql_body_keeps_the_apps_key_order() {
		let body = json!({
			"operationName": "PostComments",
			"variables": { "id": "t3_abc" },
			"extensions": { "persistedQuery": { "version": 1, "sha256Hash": "abc123" } },
		});
		assert_eq!(
			gql_payload(&body).unwrap().json,
			r#"{"operationName":"PostComments","variables":{"id":"t3_abc"},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc123"}}}"#
		);
	}

	#[test]
	fn operation_headers_are_left_out_when_the_body_lacks_them() {
		let install = fixed();
		let payload = gql_payload(&json!({ "operationName": "bad name", "variables": {} })).unwrap();
		let headers = gql_headers(&ctx(&install, 42.0), "tok", &payload, 0);
		assert_eq!(&names(&headers)[..3], ["Content-Length", "X-Reddit-Retry", "accept"]);
		assert_eq!(value(&headers, "X-Reddit-Retry"), "attempt=0, max=3");
	}

	#[test]
	fn network_and_identity_values() {
		let install = fixed();
		let headers = read_headers(&ctx(&install, 12.3456), "tok", false);
		assert_eq!(value(&headers, "X-Reddit-Http-QoS"), "GOOD");
		assert_eq!(value(&headers, "X-Reddit-Device-Tier"), "v2t1");
		assert_eq!(value(&headers, "x-reddit-compression"), "1");
		assert_eq!(value(&headers, "X-Reddit-QoS"), "down-rate-mbps=12.346");
		assert_eq!(
			value(&headers, "X-Reddit-Media-Codecs"),
			"available-codecs=video/avc, video/x-vnd.on2.vp9, video/hevc, video/av01"
		);
		assert_eq!(value(&headers, "Client-Vendor-ID"), install.device_id);
		assert_eq!(value(&headers, "x-reddit-device-id"), install.device_id);
		assert_eq!(value(&headers, "User-Agent"), "Reddit/Version 2026.44.0/Build 2644001/Android 15");
		assert_eq!(value(&headers, "X-Dev-Ad-Id"), install.ad_id);
		assert_eq!(value(&headers, "Device-Name"), "Google;Pixel 8");
		assert_eq!(value(&headers, "x-reddit-dpr"), "2.625");
		assert_eq!(value(&headers, "x-reddit-width"), "411");
		assert_eq!(value(&headers, "x-reddit-session"), TEST_SESSION);
		assert_eq!(value(&headers, "X-Reddit-P-Device-ID"), "pdev");
	}

	#[test]
	fn quality_classes_follow_the_floors() {
		let classes: Vec<&str> = [95.0, 20.0, 19.99, 10.0, 5.0, 2.0, 1.99].into_iter().map(quality).collect();
		assert_eq!(classes, ["EXCELLENT", "EXCELLENT", "GOOD", "GOOD", "STANDARD", "LIMITED", "VERY_LIMITED"]);
	}

	#[test]
	fn densities_print_as_java_floats() {
		assert_eq!(java_float(2.625), "2.625");
		assert_eq!(java_float(3.0), "3.0");
		assert_eq!(java_float(2.75), "2.75");
	}

	#[test]
	fn the_session_is_signed_as_the_app_signs_it() {
		// Pinned from Python: hmac.new(base64.b64decode(<secret>), payload, hashlib.sha512), then
		// base64.urlsafe_b64encode(...).rstrip(b"=").
		assert_eq!(
			sign_session("AbCdEfGhIjKlMnOpQr", 1_763_510_400_000),
			"AbCdEfGhIjKlMnOpQr.2.1763510400000.1ab1c15bb9f3183b5aea60ba9f1e12bde3fa4cc0960a80567455f7e106f123b1-W-LTQ_6b9wG_DMu0s7L1QhCNeiT58hnDITkjqWAoh8gxAm97hhVoig6wFPl4kV3LKM8KoT7cEtokipkifAt29g"
		);
		let fresh = new_session();
		let id = fresh.split('.').next().unwrap();
		assert_eq!(id.len(), 18);
		assert!(id.bytes().all(|b| b.is_ascii_alphanumeric()));
	}

	#[test]
	fn a_session_lasts_while_requests_keep_coming_and_is_replaced_after_30_idle_minutes() {
		let mut slot = None;
		let start = Instant::now();
		let mut started = 0;
		let mut header = |slot: &mut Option<Session>, at: Instant| {
			header_at(slot, at, || {
				started += 1;
				format!("s{started}")
			})
		};
		assert_eq!(header(&mut slot, start), "s1");
		assert_eq!(header(&mut slot, start + Duration::from_secs(29 * 60)), "s1");
		assert_eq!(header(&mut slot, start + Duration::from_secs(58 * 60)), "s1", "each request resets the idle clock");
		assert_eq!(header(&mut slot, start + Duration::from_secs(88 * 60)), "s2");
	}

	/// The request head one `send` puts on the wire, read by a one-shot local HTTP/1.1 server.
	async fn wire_head(send: impl FnOnce(String) -> RequestBuilder) -> String {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let url = format!("http://{}/", listener.local_addr().unwrap());
		let server = tokio::spawn(async move {
			let (mut socket, _) = listener.accept().await.unwrap();
			let mut raw = Vec::new();
			let mut chunk = [0; 4096];
			while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
				let n = socket.read(&mut chunk).await.unwrap();
				raw.extend_from_slice(&chunk[..n]);
			}
			socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await.unwrap();
			let head = String::from_utf8(raw).unwrap();
			head[..head.find("\r\n\r\n").unwrap()].to_string()
		});
		send(url).send().await.unwrap();
		server.await.unwrap()
	}

	/// The header names of a request head, in order, without the request line.
	fn wire_names(head: &str) -> Vec<String> {
		head.lines().skip(1).map(|line| line.split(':').next().unwrap().to_string()).collect()
	}

	/// `names` as wreq writes them on HTTP/1.1: in the listed order and case, then the Host it
	/// derives from the URL. Nothing else is added (no second Accept-Encoding, no browser headers).
	fn on_the_wire(headers: &Headers) -> Vec<String> {
		names(headers).into_iter().map(str::to_string).chain(["host".to_string()]).collect()
	}

	#[tokio::test]
	async fn the_transports_send_each_list_as_built_and_add_nothing() {
		use crate::transport::{CRONET, OKHTTP};
		let install = fixed().with_loid(Some("t2_loid".to_string()));

		let read = read_headers(&ctx(&install, 42.0), "tok", false);
		let expected = on_the_wire(&read);
		assert_eq!(wire_names(&wire_head(|url| apply(OKHTTP.get(url), read)).await), expected);

		let mint = mint_headers(&ctx(&install, 42.0));
		let expected = on_the_wire(&mint);
		assert_eq!(wire_names(&wire_head(|url| apply(OKHTTP.post(url), mint).body(MINT_BODY)).await), expected);

		let body = json!({ "operationName": "PostComments", "variables": {}, "extensions": { "persistedQuery": { "version": 1, "sha256Hash": "abc" } } });
		let payload = gql_payload(&body).unwrap();
		let gql = gql_headers(&ctx(&install, 42.0), "tok", &payload, 0);
		let expected = on_the_wire(&gql);
		let head = wire_head(|url| apply(CRONET.post(url), gql).body(payload.json)).await;
		assert_eq!(wire_names(&head), expected);
		assert!(head.contains("\r\nAccept-Encoding: gzip, deflate\r\n"), "{head}");
	}

	#[test]
	fn media_sends_the_user_agent_and_gzip_around_the_forwarded_headers() {
		let headers = media_headers("UA".to_string(), vec![("If-Modified-Since", "Thu, 19 Nov 2026 20:00:00 GMT".to_string())]);
		assert_eq!(names(&headers), ["User-Agent", "Accept", "If-Modified-Since", "Accept-Encoding"]);
		assert_eq!(value(&headers, "Accept-Encoding"), "gzip");
	}

	#[test]
	fn a_ranged_media_request_asks_for_no_encoding() {
		let headers = media_headers("UA".to_string(), vec![("Range", "bytes=0-".to_string())]);
		assert_eq!(names(&headers), ["User-Agent", "Accept", "Range"]);
	}
}
