// The token mint: one anonymous token for one app install, asked for as the app's auth client
// (OkHttp) asks (`app_wire::mint_headers`, `transport::OKHTTP`). Token lifecycle (rotation,
// budget, the daemon, which install a mint uses) is oauth.rs; the install is app_install.rs.
use crate::app_install::Install;
use crate::app_wire::{self, Ctx};
use crate::transport::OKHTTP;
use crate::upstream_log;
use log::{info, trace, warn};
use serde_json::Value;

const MINT_URL: &str = "https://www.reddit.com/auth/v2/oauth/access-token/loid";

/// What one mint returned.
pub(crate) struct Minted {
	pub(crate) token: String,
	pub(crate) expires_in: u64,
	/// The install's logged-out user id (`x-reddit-loid`), when Reddit sent a well-formed one.
	pub(crate) loid: Option<String>,
}

#[derive(Debug)]
pub(crate) enum AuthError {
	Wreq(wreq::Error),
	SerdeDeserialize(serde_json::Error),
	Field((Value, &'static str)),
}

impl From<wreq::Error> for AuthError {
	fn from(err: wreq::Error) -> Self {
		AuthError::Wreq(err)
	}
}

impl From<serde_json::Error> for AuthError {
	fn from(err: serde_json::Error) -> Self {
		AuthError::SerdeDeserialize(err)
	}
}

/// Mint one token for `install`, sending its stored loid (if any). Logs the install's device
/// prefix, never the token or the loid.
pub(crate) async fn mint(install: &Install) -> Result<Minted, AuthError> {
	let builder = app_wire::apply(OKHTTP.post(MINT_URL), app_wire::mint_headers(&Ctx::live(install))).body(app_wire::MINT_BODY);

	trace!("Minting a token for install {}...", install.device_prefix());
	let in_flight = upstream_log::start(upstream_log::Kind::Token, MINT_URL);
	let resp = builder.send().await;
	in_flight.finish(&resp);
	let resp = resp?;

	trace!("Mint answered {} with length {:?}", resp.status(), resp.headers().get("content-length"));

	// The install's logged-out user id: kept and sent on later mints, which return the same one.
	// The mint's `x-reddit-session` is ignored, as the app ignores it (app_wire signs its own).
	let loid = resp
		.headers()
		.get("x-reddit-loid")
		.map(|value| value.to_str().ok().filter(|v| is_loid(v)).map(str::to_string));
	if loid == Some(None) {
		warn!("[⛔] Mint for install {} sent a malformed x-reddit-loid; keeping the stored one", install.device_prefix());
	}

	let json: Value = resp.json().await?;
	let token = json
		.get("access_token")
		.ok_or_else(|| AuthError::Field((json.clone(), "access_token")))?
		.as_str()
		.ok_or_else(|| AuthError::Field((json.clone(), "access_token: as_str")))?
		.to_string();
	let expires_in = json
		.get("expires_in")
		.ok_or_else(|| AuthError::Field((json.clone(), "expires_in")))?
		.as_u64()
		.ok_or_else(|| AuthError::Field((json.clone(), "expires_in: as_u64")))?;

	info!("[✅] Minted a token for install {}, expires in {expires_in}s", install.device_prefix());
	Ok(Minted {
		token,
		expires_in,
		loid: loid.flatten(),
	})
}

/// A loid as Reddit hands them out (wafer's `_LOID_RE`): 1 to 2048 URL-safe token characters.
fn is_loid(value: &str) -> bool {
	(1..=2048).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~+/=:,-".contains(&b))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test(flavor = "multi_thread")]
	#[ignore = "hits live reddit"]
	async fn test_mint() {
		let minted = mint(&Install::new()).await.unwrap();
		assert!(!minted.token.is_empty());
		assert!(minted.expires_in > 0);
		assert!(minted.loid.is_some());
	}

	#[test]
	fn loids_are_url_safe_tokens() {
		assert!(is_loid("000000000abcdefgh.2.1763510400000.Z0FBQUFBQm"));
		assert!(!is_loid(""));
		assert!(!is_loid("has space"));
		assert!(!is_loid("line\nbreak"));
		assert!(!is_loid(&"a".repeat(2049)));
	}
}
