use crate::app_install::{self, Install};
use crate::oauth_device::{self, AuthError};
use arc_swap::ArcSwap;
use log::{error, info, trace, warn};
use std::{
	future::Future,
	sync::{
		atomic::{AtomicBool, AtomicU16, Ordering},
		Arc,
	},
	time::{Duration, Instant},
};
use tokio::sync::OnceCell;
use tokio::time::timeout;

const OAUTH_MAX_ATTEMPTS: u32 = 10;
const OAUTH_TIMEOUT: Duration = Duration::from_secs(5);

// A token younger than this is never rotated for being blocked: if a fresh token is
// refused too, the block is on the IP, and minting more would only hammer the auth endpoint.
const BLOCKED_TOKEN_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

// Requests a freshly minted token may make before `client::fetch_reddit` rolls it over early.
// `startup_check::rate_limit_check` asserts a fresh token reports exactly this after one request.
pub(crate) const FRESH_TOKEN_BUDGET: u16 = 99;

// The daemon rotates this long before expiry, but never sooner than the floor after a mint, so a
// short or zero `expires_in` from Reddit cannot turn the daemon into a mint loop.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(120);
const TOKEN_REFRESH_FLOOR: Duration = Duration::from_secs(60);

/// One anonymous token and the app install it was minted for (the install carries the loid that
/// mint returned). No `Debug`: neither the token nor the loid may reach a log.
#[derive(Clone)]
pub struct Oauth {
	token: String,
	expires_in: u64,
	minted_at: Instant,
	pub(crate) install: Install,
}

impl Oauth {
	/// Mint a token for `install`, retried up to OAUTH_MAX_ATTEMPTS times; Err once they are
	/// spent. Callers in production exit on Err (see `exit_for_restart`).
	async fn mint_with_retries(install: Install) -> Result<Self, String> {
		// (Upstream also carries a GenericWebAuth fallback; Reddit answers 401 to its
		// hardcoded client id, in upstream too, so it was removed here — see docs/fork.md.)
		for attempt in 1..=OAUTH_MAX_ATTEMPTS {
			match timeout(OAUTH_TIMEOUT, oauth_device::mint(&install)).await {
				Ok(Ok(minted)) => {
					info!("[✅] Successfully created OAuth client");
					return Ok(Self {
						token: minted.token,
						expires_in: minted.expires_in,
						minted_at: Instant::now(),
						install: install.with_loid(minted.loid),
					});
				}
				Ok(Err(e)) => {
					error!(
						"[⛔] Failed to create OAuth client (attempt {attempt}/{OAUTH_MAX_ATTEMPTS}): {}",
						match e {
							AuthError::Wreq(error) => error.to_string(),
							AuthError::SerdeDeserialize(error) => error.to_string(),
							AuthError::Field((value, error)) => format!("{error}\n{value}"),
						}
					);
				}
				Err(_) => {
					error!("[⛔] Failed to create OAuth client before timeout (attempt {attempt}/{OAUTH_MAX_ATTEMPTS})");
				}
			}

			if attempt < OAUTH_MAX_ATTEMPTS {
				tokio::time::sleep(OAUTH_TIMEOUT).await;
			}
		}

		Err(format!("Failed to create OAuth client after {OAUTH_MAX_ATTEMPTS} attempts"))
	}

	pub(crate) fn token(&self) -> &str {
		&self.token
	}

	pub fn user_agent(&self) -> String {
		self.install.user_agent()
	}
}

/// The test seam for token rotation: one complete mint for `install` (retries included), the only
/// network call `TokenManager` makes. Production uses `MobileSpoofMinter`; the offline tests below
/// use a fake.
pub(crate) trait Minter: Send + Sync + 'static {
	fn mint(&self, install: Install) -> impl Future<Output = Result<Oauth, String>> + Send;
}

/// Production minter: the app install against Reddit's auth endpoint. Saves the install before
/// minting and again after a mint succeeds (for the loid Reddit returns). The first save is for a
/// block's replacement: if its mints all fail, the process exits, and the restart must load the
/// new install, not the flagged one. For a renewal it rewrites the same row.
pub(crate) struct MobileSpoofMinter;

impl Minter for MobileSpoofMinter {
	async fn mint(&self, install: Install) -> Result<Oauth, String> {
		app_install::persist(&install);
		let oauth = Oauth::mint_with_retries(install).await?;
		app_install::persist(&oauth.install);
		Ok(oauth)
	}
}

/// Which install a rotation mints for. A renewal (the daemon, a low budget, a 401) is the same
/// app asking again; only a block replaces it (see `TokenManager::rotate_blocked`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InstallChoice {
	Keep,
	Replace,
}

/// What a rotation request did. Production logs it (and exits on `Failed`); tests assert it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rotation {
	Rotated,
	/// Another caller is mid-mint; this one returned at once without minting.
	AlreadyRotating,
	/// A blocked-token rotation was refused: the current token is younger than the cooldown.
	CoolingDown,
	/// Every mint attempt failed. The current token is unchanged and the next rotation may retry.
	Failed(String),
}

/// Owns the live token and every rule for replacing it: single-flight rotation, the per-token
/// request budget, and the blocked-token cooldown. One process-wide instance lives behind
/// `oauth_session()`; tests build their own over a fake `Minter`.
pub(crate) struct TokenManager<M> {
	current: ArcSwap<Oauth>,
	rolling_over: AtomicBool,
	ratelimit_remaining: AtomicU16,
	minter: M,
}

impl<M: Minter> TokenManager<M> {
	pub(crate) async fn bootstrap(minter: M, install: Install) -> Result<Self, String> {
		let first = minter.mint(install).await?;
		Ok(Self {
			current: ArcSwap::from_pointee(first),
			rolling_over: AtomicBool::new(false),
			ratelimit_remaining: AtomicU16::new(FRESH_TOKEN_BUDGET),
			minter,
		})
	}

	pub(crate) fn current(&self) -> &ArcSwap<Oauth> {
		&self.current
	}

	/// Remaining request budget for the current token, per Reddit's `x-ratelimit-remaining`.
	pub(crate) fn ratelimit_remaining(&self) -> &AtomicU16 {
		&self.ratelimit_remaining
	}

	/// Count one request against the budget, stopping at 0. A plain `fetch_sub` at 0 wraps the
	/// u16 to 65535, and fetch_reddit's `< 10` low-budget refresh then never fires (upstream bc8c9ec).
	pub(crate) fn consume_request(&self) {
		let _ = self.ratelimit_remaining.try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1));
	}

	pub(crate) fn is_rolling_over(&self) -> bool {
		self.rolling_over.load(Ordering::SeqCst)
	}

	/// Renew the token for the same install and swap it in.
	pub(crate) async fn rotate(&self) -> Rotation {
		self.rotate_with(InstallChoice::Keep).await
	}

	/// Mint a token for the install `choice` names and swap it in. Single-flight: a call while
	/// another is minting returns `AlreadyRotating` instead of minting twice.
	async fn rotate_with(&self, choice: InstallChoice) -> Rotation {
		if self.rolling_over.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
			trace!("Skipping refresh token roll over, already in progress");
			return Rotation::AlreadyRotating;
		}
		// Clears the flag even if this future is dropped mid-mint (a request whose client went
		// away). Without it the flag stayed set forever and no token was ever rotated again.
		let _guard = RollingOverGuard(&self.rolling_over);

		trace!("Rolling over refresh token. Current rate limit: {}", self.ratelimit_remaining.load(Ordering::SeqCst));
		let install = match choice {
			InstallChoice::Keep => {
				let install = self.current.load().install.clone();
				info!("[🔄] same install {}, renewing token", install.device_prefix());
				install
			}
			InstallChoice::Replace => {
				let install = Install::new();
				info!("[🔄] new install {}", install.device_prefix());
				install
			}
		};
		match self.minter.mint(install).await {
			Ok(new_client) => {
				self.current.store(Arc::new(new_client));
				self.ratelimit_remaining.store(FRESH_TOKEN_BUDGET, Ordering::SeqCst);
				info!("[🔄] OAuth token rotated");
				Rotation::Rotated
			}
			Err(e) => Rotation::Failed(e),
		}
	}

	/// Reddit sometimes flags a long-lived token/device pair and answers every request with a
	/// 403 HTML "blocked due to a network policy" page, while a freshly minted pair from the same
	/// IP works (Oct 2026). So a block, unlike a renewal, replaces the install: a new device,
	/// phone and ids, and no loid.
	pub(crate) async fn rotate_blocked(&self) -> Rotation {
		let age = self.current.load().minted_at.elapsed();
		if age < BLOCKED_TOKEN_REFRESH_COOLDOWN {
			warn!("[🚫] Reddit blocked a token minted {age:?} ago; not rotating again yet (possible IP-level block)");
			return Rotation::CoolingDown;
		}
		warn!("[🚫] Reddit blocked the current token (minted {age:?} ago). Replacing the install...");
		self.rotate_with(InstallChoice::Replace).await
	}
}

struct RollingOverGuard<'a>(&'a AtomicBool);

impl Drop for RollingOverGuard<'_> {
	fn drop(&mut self) {
		self.0.store(false, Ordering::SeqCst);
	}
}

/// How long the daemon waits before rotating a token that expires in `expires_in` seconds.
fn refresh_delay(expires_in: u64) -> Duration {
	Duration::from_secs(expires_in).saturating_sub(TOKEN_REFRESH_MARGIN).max(TOKEN_REFRESH_FLOOR)
}

/// Production policy for a mint that exhausted its retries, at bootstrap and on rotation alike:
/// exit and let the container restart policy take over (AGENTS.md "Startup order").
pub(crate) fn exit_for_restart(reason: &str) -> ! {
	error!("[⛔] {reason}; exiting for the restart policy");
	std::process::exit(1);
}

// Populated once by `init_oauth_client()` at startup. This used to be a `LazyLock` whose
// initializer ran `futures_lite::block_on(Oauth::new())` from inside the tokio runtime; a
// nested foreign executor never resets tokio's cooperative budget, so on a slow/degraded
// network every timer and socket returned Pending+wake forever and the main thread spun at
// 100% CPU before the server ever listened (Sept 2026 outage). Bootstrapping must stay async.
static OAUTH_SESSION: OnceCell<TokenManager<MobileSpoofMinter>> = OnceCell::const_new();

/// Bootstraps the OAuth client for the stored app install (a new one on the first start) and
/// starts the token-refresh daemon. Must complete, inside the tokio runtime, before anything calls
/// `oauth_client()`, and after `db::init()`. Idempotent: concurrent or repeated
/// calls (tests) share the first initialization. Exits the process if every mint attempt fails.
pub async fn init_oauth_client() {
	let bootstrap = async {
		TokenManager::bootstrap(MobileSpoofMinter, app_install::load_or_create())
			.await
			.unwrap_or_else(|e| exit_for_restart(&e))
	};
	init_then(&OAUTH_SESSION, bootstrap, || {
		tokio::spawn(token_daemon());
	})
	.await;
}

/// Fills `cell` with `init` and then, only on the call that ran `init`, runs `started`, once the
/// cell holds the value. The token daemon reads the session at once: spawned inside
/// get_or_init it raced the store, panicked in `oauth_session()` on 5 of 16 boots (Loki,
/// 2026-10) and, a panicked task being silent, left those boots without token refresh.
async fn init_then<T>(cell: &OnceCell<T>, init: impl Future<Output = T>, started: impl FnOnce()) {
	let mut ran = false;
	let first = &mut ran;
	cell
		.get_or_init(|| async move {
			*first = true;
			init.await
		})
		.await;
	if ran {
		started();
	}
}

/// The live token manager: current token, request budget, rotation. Panics if
/// `init_oauth_client()` has not completed — that is a startup-ordering bug in `main`, never a
/// runtime condition.
pub(crate) fn oauth_session() -> &'static TokenManager<MobileSpoofMinter> {
	OAUTH_SESSION.get().expect("OAuth client used before init_oauth_client() completed")
}

/// The live OAuth client (token + the app install it was minted for).
pub fn oauth_client() -> &'static ArcSwap<Oauth> {
	oauth_session().current()
}

fn exit_on_failed_mint(outcome: Rotation) {
	if let Rotation::Failed(e) = outcome {
		exit_for_restart(&e);
	}
}

pub async fn token_daemon() {
	loop {
		let duration = refresh_delay(oauth_session().current().load().expires_in);

		info!("[⏳] Waiting for {duration:?} seconds before refreshing OAuth token...");

		tokio::time::sleep(duration).await;

		info!("[⌛] {duration:?} Elapsed! Refreshing OAuth token...");

		force_refresh_token().await;
	}
}

pub async fn force_refresh_token() {
	exit_on_failed_mint(oauth_session().rotate().await);
}

/// Used by `client::fetch_reddit` on a non-JSON 403; see `TokenManager::rotate_blocked`.
pub async fn refresh_blocked_token() {
	exit_on_failed_mint(oauth_session().rotate_blocked().await);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn the_daemon_starts_once_and_only_after_the_session_is_stored() {
		let cell = OnceCell::new();
		let started = std::cell::Cell::new(0);
		for _ in 0..2 {
			init_then(&cell, async { 7 }, || {
				assert_eq!(cell.get(), Some(&7));
				started.set(started.get() + 1);
			})
			.await;
		}
		assert_eq!(started.get(), 1);
	}

	#[tokio::test(flavor = "multi_thread")]
	#[ignore = "hits live reddit"]
	async fn test_oauth_client() {
		// Integration test - tests the overall Oauth client
		init_oauth_client().await;
		assert!(!oauth_client().load_full().token().is_empty());
	}

	#[tokio::test(flavor = "multi_thread")]
	#[ignore = "hits live reddit"]
	async fn test_oauth_client_refresh() {
		init_oauth_client().await;
		force_refresh_token().await;
	}

	#[tokio::test(flavor = "multi_thread")]
	#[ignore = "hits live reddit"]
	async fn test_oauth_install_has_a_loid() {
		init_oauth_client().await;
		assert!(!oauth_client().load_full().install.loid.is_empty());
	}

	// Offline: a fake Minter stands in for Reddit's auth endpoint (AGENTS.md "Test seams").

	use std::sync::atomic::AtomicUsize;
	use std::sync::Mutex;
	use tokio::sync::Notify;

	/// A token named `token` for `install`, minted `age` ago, without touching the network.
	fn fake_oauth(token: &str, age: Duration, install: Install) -> Oauth {
		Oauth {
			token: token.to_owned(),
			expires_in: 86_400,
			minted_at: Instant::now().checked_sub(age).expect("test host has been up longer than the token age"),
			install,
		}
	}

	/// Mints `tok-1`, `tok-2`, ... (aged `age`) and hands out `loid-<n>` as Reddit hands out a
	/// loid, or fails while `fail` is set. Records the install each mint was asked for. With
	/// `gate`, each mint first waits for one `notify_one`, so a test can hold a rotation mid-mint.
	#[derive(Default)]
	struct FakeMinter {
		calls: AtomicUsize,
		fail: AtomicBool,
		age: Duration,
		gate: Option<Arc<Notify>>,
		asked: Mutex<Vec<Install>>,
	}

	impl Minter for FakeMinter {
		async fn mint(&self, install: Install) -> Result<Oauth, String> {
			if let Some(gate) = &self.gate {
				gate.notified().await;
			}
			self.asked.lock().unwrap().push(install.clone());
			let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
			if self.fail.load(Ordering::SeqCst) {
				return Err(format!("mint {n} refused"));
			}
			Ok(fake_oauth(&format!("tok-{n}"), self.age, install.with_loid(Some(format!("loid-{n}")))))
		}
	}

	/// The install the `n`th mint (1-based) was asked for.
	fn asked(manager: &TokenManager<FakeMinter>, n: usize) -> Install {
		manager.minter.asked.lock().unwrap()[n - 1].clone()
	}

	/// Gated tests deadlock if single-flight breaks; fail them instead of hanging the suite.
	async fn bounded<T>(fut: impl Future<Output = T>) -> T {
		tokio::time::timeout(Duration::from_secs(5), fut)
			.await
			.expect("rotation deadlocked: more mints than the gate releases")
	}

	fn bearer<M: Minter>(manager: &TokenManager<M>) -> String {
		manager.current().load().token().to_owned()
	}

	fn device<M: Minter>(manager: &TokenManager<M>) -> String {
		manager.current().load().install.device_id.clone()
	}

	async fn manager(minter: FakeMinter) -> TokenManager<FakeMinter> {
		if let Some(gate) = &minter.gate {
			gate.notify_one(); // let the bootstrap mint through
		}
		TokenManager::bootstrap(minter, Install::new()).await.unwrap()
	}

	#[tokio::test]
	async fn bootstrap_mints_once_with_a_full_budget() {
		let m = manager(FakeMinter::default()).await;
		assert_eq!(bearer(&m), "tok-1");
		assert_eq!(m.minter.calls.load(Ordering::SeqCst), 1);
		assert_eq!(m.ratelimit_remaining().load(Ordering::SeqCst), FRESH_TOKEN_BUDGET);
		assert!(!m.is_rolling_over());
	}

	#[tokio::test]
	async fn consume_request_stops_at_zero() {
		let m = manager(FakeMinter::default()).await;
		m.ratelimit_remaining().store(1, Ordering::SeqCst);
		m.consume_request();
		m.consume_request();
		assert_eq!(m.ratelimit_remaining().load(Ordering::SeqCst), 0);
	}

	#[tokio::test]
	async fn bootstrap_failure_is_an_error() {
		let minter = FakeMinter::default();
		minter.fail.store(true, Ordering::SeqCst);
		assert_eq!(TokenManager::bootstrap(minter, Install::new()).await.err(), Some("mint 1 refused".to_owned()));
	}

	// The expired-token path: fetch_reddit's 401 handling and the daemon both land here.
	#[tokio::test]
	async fn rotate_swaps_the_token_and_restores_the_budget() {
		let m = manager(FakeMinter::default()).await;
		m.ratelimit_remaining().store(3, Ordering::SeqCst);
		assert_eq!(m.rotate().await, Rotation::Rotated);
		assert_eq!(bearer(&m), "tok-2");
		assert_eq!(m.ratelimit_remaining().load(Ordering::SeqCst), FRESH_TOKEN_BUDGET);
		assert!(!m.is_rolling_over());
	}

	#[tokio::test]
	async fn failed_rotation_keeps_the_old_token_and_allows_a_retry() {
		let m = manager(FakeMinter::default()).await;
		m.minter.fail.store(true, Ordering::SeqCst);
		assert_eq!(m.rotate().await, Rotation::Failed("mint 2 refused".to_owned()));
		assert_eq!(bearer(&m), "tok-1");
		assert!(!m.is_rolling_over(), "a failed mint must not leave the rotation flag set");

		m.minter.fail.store(false, Ordering::SeqCst);
		assert_eq!(m.rotate().await, Rotation::Rotated);
		assert_eq!(bearer(&m), "tok-3");
	}

	#[tokio::test]
	async fn concurrent_rotations_mint_once() {
		let gate = Arc::new(Notify::new());
		let m = manager(FakeMinter {
			gate: Some(gate.clone()),
			..FakeMinter::default()
		})
		.await;
		// join! polls in order: the first rotation takes the flag and parks in the gated mint,
		// the second sees the flag, then releases the gate.
		let (first, second) = bounded(async {
			tokio::join!(m.rotate(), async {
				let r = m.rotate().await;
				gate.notify_one();
				r
			})
		})
		.await;
		assert_eq!((first, second), (Rotation::Rotated, Rotation::AlreadyRotating));
		assert_eq!(m.minter.calls.load(Ordering::SeqCst), 2);
	}

	#[tokio::test]
	async fn a_dropped_rotation_does_not_wedge_the_flag() {
		let gate = Arc::new(Notify::new());
		let m = manager(FakeMinter {
			gate: Some(gate.clone()),
			..FakeMinter::default()
		})
		.await;
		{
			let mut abandoned = std::pin::pin!(m.rotate());
			assert!(futures_lite::future::poll_once(&mut abandoned).await.is_none(), "mint should be parked on the gate");
			assert!(m.is_rolling_over());
		}
		assert!(!m.is_rolling_over());
		gate.notify_one();
		assert_eq!(bounded(m.rotate()).await, Rotation::Rotated);
	}

	// The 403 self-heal: rotate once, then refuse until the cooldown passes, so a block that
	// survives rotation (an IP-level one) never becomes a mint per request.
	#[tokio::test]
	async fn blocked_token_rotates_once_then_cools_down() {
		let m = manager(FakeMinter {
			age: Duration::ZERO,
			..FakeMinter::default()
		})
		.await;
		let install = m.current().load().install.clone();
		m.current()
			.store(Arc::new(fake_oauth("long-lived", BLOCKED_TOKEN_REFRESH_COOLDOWN + Duration::from_secs(1), install)));

		assert_eq!(m.rotate_blocked().await, Rotation::Rotated);
		assert_eq!(bearer(&m), "tok-2");
		for _ in 0..3 {
			assert_eq!(m.rotate_blocked().await, Rotation::CoolingDown);
		}
		assert_eq!(m.minter.calls.load(Ordering::SeqCst), 2, "one bootstrap mint plus exactly one rotation");
	}

	#[tokio::test]
	async fn a_fresh_token_is_never_rotated_for_a_block() {
		let m = manager(FakeMinter::default()).await;
		assert_eq!(m.rotate_blocked().await, Rotation::CoolingDown);
		assert_eq!(bearer(&m), "tok-1");
	}

	// A renewal is the same app asking again: same device, and it sends the loid it was given.
	#[tokio::test]
	async fn a_renewal_keeps_the_install_and_sends_its_loid() {
		let m = manager(FakeMinter::default()).await;
		let first = device(&m);
		assert_eq!(m.rotate().await, Rotation::Rotated);
		assert_eq!(device(&m), first);
		assert_eq!((asked(&m, 2).device_id, asked(&m, 2).loid.as_str().to_owned()), (first, "loid-1".to_owned()));
		assert_eq!(m.current().load().install.loid, "loid-2", "the loid Reddit returns is kept");
	}

	// A block replaces the install: a new device and ids, minted without a loid.
	#[tokio::test]
	async fn a_blocked_rotation_mints_for_a_new_install() {
		let m = manager(FakeMinter::default()).await;
		let blocked = m.current().load().install.clone();
		m.current()
			.store(Arc::new(fake_oauth("flagged", BLOCKED_TOKEN_REFRESH_COOLDOWN + Duration::from_secs(1), blocked.clone())));

		assert_eq!(m.rotate_blocked().await, Rotation::Rotated);
		let fresh = asked(&m, 2);
		assert_ne!(fresh.device_id, blocked.device_id);
		assert_ne!(fresh.ad_id, blocked.ad_id);
		assert_ne!(fresh.p_device_id, blocked.p_device_id);
		assert!(fresh.loid.is_empty());
		assert_eq!(device(&m), fresh.device_id);
	}

	#[test]
	fn refresh_delay_leaves_a_margin_and_has_a_floor() {
		assert_eq!(refresh_delay(86_400), Duration::from_secs(86_280));
		assert_eq!(refresh_delay(150), TOKEN_REFRESH_FLOOR);
		assert_eq!(refresh_delay(0), TOKEN_REFRESH_FLOOR, "a zero expiry must not spin the daemon");
	}
}
