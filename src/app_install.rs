//! The one Android-app install redlib presents itself as: a device id, a Play release, an Android
//! version, a phone and the logged-out user id (loid) Reddit gave it. It is kept in SQLite
//! (`db::AppInstallRow`) across restarts and token renewals, as a real install keeps its identity,
//! and replaced only when Reddit blocks it (`oauth::TokenManager::rotate_blocked`). The headers an
//! install sends are `app_wire`.
//!
//! The release table, the phones and the value formats are ported from Averyy/wafer
//! (Apache-2.0): `wafer/_reddit_app.py` and
//! https://github.com/Averyy/wafer/blob/main/docs/ref-reddit.md, which checked them against the
//! real app 2026.44.0.

use crate::db::{self, AppInstallRow};
use log::{info, warn};

/// A Play release: version name, versionCode and the minimum Android major it installs on.
#[derive(PartialEq)]
pub(crate) struct Release {
	pub(crate) version: &'static str,
	pub(crate) build: u32,
	pub(crate) min_android: u8,
}

// Hand-maintained, oldest first: refresh it as the app updates (an install that never updates is
// unusual, and Reddit can retire old builds). Source: the Play listing or an APKMirror listing,
// with each release's minimum Android. A stored release that leaves this table moves to the
// newest one its Android takes, as an app update would. These are wafer's, October 2026.
const RELEASES: &[Release] = &[
	Release {
		version: "2026.42.0",
		build: 2_642_001,
		min_android: 12,
	},
	Release {
		version: "2026.43.0",
		build: 2_643_041,
		min_android: 10,
	},
	Release {
		version: "2026.44.0",
		build: 2_644_001,
		min_android: 10,
	},
];

/// The Android majors a new install runs (`Build.VERSION.RELEASE`, a plain major since 13).
const ANDROID_MAJORS: &[u8] = &[13, 14, 15, 16];

const AVC: &str = "video/avc";
const VP9: &str = "video/x-vnd.on2.vp9";
const HEVC: &str = "video/hevc";
const AV1: &str = "video/av01";

/// A phone whose display metrics and hardware decoders are known.
#[derive(PartialEq)]
pub(crate) struct Phone {
	/// `Build.MODEL`
	pub(crate) model: &'static str,
	/// `Build.MANUFACTURER`
	pub(crate) manufacturer: &'static str,
	pub(crate) density: f32,
	pub(crate) width_px: u32,
	/// Hardware video decoders, in the order the app lists them.
	pub(crate) codecs: &'static [&'static str],
	/// The Android major it shipped with: an install never runs an older one.
	pub(crate) shipped_android: u8,
}

const PIXEL_CODECS: &[&str] = &[AVC, VP9, HEVC, AV1];

const PHONES: &[Phone] = &[
	Phone {
		model: "Pixel 7",
		manufacturer: "Google",
		density: 2.625,
		width_px: 1080,
		codecs: PIXEL_CODECS,
		shipped_android: 13,
	},
	Phone {
		model: "Pixel 7a",
		manufacturer: "Google",
		density: 2.625,
		width_px: 1080,
		codecs: PIXEL_CODECS,
		shipped_android: 13,
	},
	Phone {
		model: "Pixel 8",
		manufacturer: "Google",
		density: 2.625,
		width_px: 1080,
		codecs: PIXEL_CODECS,
		shipped_android: 14,
	},
	Phone {
		model: "Pixel 8a",
		manufacturer: "Google",
		density: 2.625,
		width_px: 1080,
		codecs: PIXEL_CODECS,
		shipped_android: 14,
	},
	Phone {
		model: "Pixel 9",
		manufacturer: "Google",
		density: 2.625,
		width_px: 1080,
		codecs: PIXEL_CODECS,
		shipped_android: 14,
	},
];

/// One app install on one phone. No `Debug`: it carries the loid, which never reaches a log; the
/// 8-char `device_prefix` is what logs name it by.
#[derive(Clone, PartialEq)]
pub struct Install {
	/// uuid4, sent as `Client-Vendor-ID` and `x-reddit-device-id`.
	pub(crate) device_id: String,
	pub(crate) release: &'static Release,
	pub(crate) android: u8,
	/// The download rate the app estimates, in Mbps; each request reports a sample around it.
	pub(crate) down_rate: f64,
	pub(crate) phone: &'static Phone,
	/// The Google advertising id (`X-Dev-Ad-Id`), a uuid4.
	pub(crate) ad_id: String,
	/// Lowercase hex SHA-384 of the phone's `Settings.Secure.ANDROID_ID` (`X-Reddit-P-Device-ID`).
	pub(crate) p_device_id: String,
	/// The logged-out user id from the mint's `x-reddit-loid`; empty until the first mint.
	pub(crate) loid: String,
}

impl Install {
	/// A fresh install: new ids, a random Android major, a release and phone it can run, no loid.
	pub(crate) fn new() -> Self {
		let android = pick(ANDROID_MAJORS.iter().copied()).expect("ANDROID_MAJORS is not empty");
		let release = pick(RELEASES.iter().filter(|r| r.min_android <= android)).expect("every Android major takes a release");
		Self {
			device_id: uuid::Uuid::new_v4().to_string(),
			release,
			android,
			down_rate: round3(8.0 + fastrand::f64() * 87.0),
			phone: phone_for(android).expect("every Android major has a phone"),
			ad_id: uuid::Uuid::new_v4().to_string(),
			p_device_id: p_device_id(&format!("{:016x}", fastrand::u64(..))),
			loid: String::new(),
		}
	}

	/// The stored install, brought up to date: a release no longer in `RELEASES` moves to the
	/// newest one its Android takes, and a phone no longer in `PHONES` (or newer than its Android)
	/// is replaced; the ids and the loid stay. A row that cannot be an install is replaced whole.
	fn from_row(row: &AppInstallRow) -> Self {
		let Some((android, down_rate)) = u8::try_from(row.android).ok().zip(row.down_rate.parse::<f64>().ok()) else {
			warn!("[📱] stored install {} is unreadable; starting a new one", prefix(&row.device_id));
			return Self::new();
		};
		let stored = RELEASES.iter().find(|r| r.version == row.version && i64::from(r.build) == row.build);
		let (Some(release), Some(phone)) = (
			stored.or_else(|| newest_release_for(android)),
			PHONES.iter().find(|p| p.model == row.model && p.shipped_android <= android).or_else(|| phone_for(android)),
		) else {
			warn!(
				"[📱] stored install {} runs Android {android}, which no release or phone takes; starting a new one",
				prefix(&row.device_id)
			);
			return Self::new();
		};
		Self {
			device_id: row.device_id.clone(),
			release,
			android,
			down_rate,
			phone,
			ad_id: row.ad_id.clone(),
			p_device_id: row.p_device_id.clone(),
			loid: row.loid.clone(),
		}
	}

	fn to_row(&self) -> AppInstallRow {
		AppInstallRow {
			device_id: self.device_id.clone(),
			version: self.release.version.to_string(),
			build: i64::from(self.release.build),
			android: i64::from(self.android),
			down_rate: format!("{:.3}", self.down_rate),
			model: self.phone.model.to_string(),
			ad_id: self.ad_id.clone(),
			p_device_id: self.p_device_id.clone(),
			loid: self.loid.clone(),
		}
	}

	/// This install after a mint: Reddit's loid when it sent one, else the one it had.
	pub(crate) fn with_loid(mut self, loid: Option<String>) -> Self {
		if let Some(loid) = loid {
			self.loid = loid;
		}
		self
	}

	pub(crate) fn user_agent(&self) -> String {
		format!("Reddit/Version {}/Build {}/Android {}", self.release.version, self.release.build, self.android)
	}

	/// What logs name the install by.
	pub(crate) fn device_prefix(&self) -> &str {
		prefix(&self.device_id)
	}

	/// One request's bandwidth estimate: the install's rate, varied by up to 15% either way.
	pub(crate) fn sample_down_rate(&self) -> f64 {
		self.down_rate * (0.85 + fastrand::f64() * 0.3)
	}
}

/// The stored install (brought up to date by `Install::from_row`), or a new one, saved either way.
/// `oauth::init_oauth_client` calls it once, before the first mint.
pub(crate) fn load_or_create() -> Install {
	let Some(row) = db::load_app_install() else {
		let install = Install::new();
		info!("[📱] new install {} ({}, {})", install.device_prefix(), install.user_agent(), install.phone.model);
		persist(&install);
		return install;
	};
	let install = Install::from_row(&row);
	if install.to_row() != row {
		info!(
			"[📱] stored install {} updated to {} on a {}",
			install.device_prefix(),
			install.user_agent(),
			install.phone.model
		);
		persist(&install);
	}
	info!("[📱] using install {} ({}, {})", install.device_prefix(), install.user_agent(), install.phone.model);
	install
}

/// Save `install` as the one install. Called after every successful mint (`oauth::MobileSpoofMinter`).
pub(crate) fn persist(install: &Install) {
	db::save_app_install(&install.to_row());
}

fn pick<T>(candidates: impl Iterator<Item = T>) -> Option<T> {
	let mut candidates: Vec<T> = candidates.collect();
	if candidates.is_empty() {
		return None;
	}
	Some(candidates.swap_remove(fastrand::usize(..candidates.len())))
}

fn newest_release_for(android: u8) -> Option<&'static Release> {
	RELEASES.iter().rev().find(|r| r.min_android <= android)
}

fn phone_for(android: u8) -> Option<&'static Phone> {
	pick(PHONES.iter().filter(|p| p.shipped_android <= android))
}

/// `X-Reddit-P-Device-ID` for an `ANDROID_ID` (16 lowercase hex chars on the phone).
fn p_device_id(android_id: &str) -> String {
	boring2::sha::sha384(android_id.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn round3(value: f64) -> f64 {
	(value * 1000.0).round() / 1000.0
}

fn prefix(device_id: &str) -> &str {
	device_id.get(..8).unwrap_or(device_id)
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;

	/// A fixed install for header tests: Android 15 on a Pixel 8, release 2026.44.0.
	pub(crate) fn fixed() -> Install {
		Install {
			device_id: "0f8fad5b-d9cb-469f-a165-70867728950e".to_string(),
			release: &RELEASES[2],
			android: 15,
			down_rate: 42.125,
			phone: &PHONES[2],
			ad_id: "7c9e6679-7425-40de-944b-e07fc1f90ae7".to_string(),
			p_device_id: "pdev".to_string(),
			loid: String::new(),
		}
	}

	#[test]
	fn a_new_install_is_one_the_table_allows() {
		for _ in 0..200 {
			let install = Install::new();
			assert!(ANDROID_MAJORS.contains(&install.android));
			assert!(install.release.min_android <= install.android);
			assert!(install.phone.shipped_android <= install.android, "{} on Android {}", install.phone.model, install.android);
			assert!((8.0..=95.0).contains(&install.down_rate));
			assert_eq!(install.down_rate, round3(install.down_rate));
			assert_eq!(install.p_device_id.len(), 96);
			assert!(install.loid.is_empty());
			let sample = install.sample_down_rate();
			assert!(sample >= install.down_rate * 0.85 && sample <= install.down_rate * 1.15);
		}
		assert_ne!(Install::new().device_id, Install::new().device_id);
	}

	#[test]
	fn every_android_major_has_a_release_and_a_phone() {
		for &android in ANDROID_MAJORS {
			assert!(newest_release_for(android).is_some(), "Android {android}");
			assert!(PHONES.iter().any(|p| p.shipped_android <= android), "Android {android}");
		}
	}

	#[test]
	fn p_device_id_is_the_lowercase_hex_sha384_of_the_android_id() {
		// Pinned from Python: hashlib.sha384(b"0123456789abcdef").hexdigest()
		assert_eq!(
			p_device_id("0123456789abcdef"),
			"fc6304023487cb6f85ac80e47817760c6b153c02da46c6429649e963b031e525deb160e3da5b645fa843fab2f25b913f"
		);
	}

	#[test]
	fn user_agent_names_release_build_and_android() {
		assert_eq!(fixed().user_agent(), "Reddit/Version 2026.44.0/Build 2644001/Android 15");
		assert_eq!(fixed().device_prefix(), "0f8fad5b");
	}

	#[test]
	fn a_stored_install_round_trips() {
		let install = fixed().with_loid(Some("t2_loid".to_string()));
		let row = install.to_row();
		assert_eq!((row.version.as_str(), row.build, row.down_rate.as_str()), ("2026.44.0", 2_644_001, "42.125"));
		assert!(Install::from_row(&row) == install);
	}

	#[test]
	fn a_mint_without_a_loid_keeps_the_stored_one() {
		let install = fixed().with_loid(Some("t2_first".to_string())).with_loid(None);
		assert_eq!(install.loid, "t2_first");
	}

	#[test]
	fn a_retired_release_updates_and_keeps_the_ids() {
		let mut row = fixed().with_loid(Some("t2_loid".to_string())).to_row();
		row.version = "2026.28.0".to_string();
		row.build = 2_628_061;
		let updated = Install::from_row(&row);
		assert_eq!(updated.release.version, "2026.44.0", "the newest release Android 15 takes");
		assert_eq!(
			(updated.device_id.as_str(), updated.loid.as_str(), updated.phone.model),
			(row.device_id.as_str(), "t2_loid", "Pixel 8")
		);
	}

	#[test]
	fn an_unknown_phone_is_replaced_and_the_ids_kept() {
		let mut row = fixed().to_row();
		row.model = "Nexus 5".to_string();
		let updated = Install::from_row(&row);
		assert!(PHONES.iter().any(|p| p.model == updated.phone.model));
		assert!(updated.phone.shipped_android <= 15);
		assert_eq!((updated.device_id, updated.ad_id), (row.device_id, row.ad_id));
	}

	#[test]
	fn an_unreadable_row_starts_a_new_install() {
		let mut row = fixed().to_row();
		row.android = 300;
		assert_ne!(Install::from_row(&row).device_id, row.device_id);
	}
}
