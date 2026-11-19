//! The Android app's two network stacks as two pooled HTTP clients, so each request to Reddit
//! goes out with the TLS and HTTP/2 of the app's client that sends it:
//! - `OKHTTP`: OkHttp on Android's Conscrypt, for the token mint, REST reads and the media proxy.
//! - `CRONET`: the app's embedded Cronet 143, for GraphQL on gql-fed.
//!
//! Neither sets a default header: every request carries the app's full header list
//! (`app_wire`). This sits below everything that talks to Reddit (oauth_device, client,
//! media_proxy) and imports none of them, which keeps the module graph one-way.
//!
//! The OkHttp ClientHello and HTTP/2 settings are ported from Averyy/wafer (Apache-2.0),
//! `okhttp_tls_options()` / `okhttp_http2_options()` / `cronet_emulation()` in
//! `wafer/_reddit_app.py`, matched there to captures of the real app 2026.44.0 (JA4
//! t13d1514h2_8daaf6152771_43ade6aba3df for OkHttp; Cronet's equals wreq's Chrome143 on Android).
use log::info;
use std::sync::LazyLock;
use wreq::http2::{Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder};
use wreq::redirect::Policy;
use wreq::tls::{AlpnProtocol, ExtensionType, TlsOptions, TlsVersion};
use wreq::{Client as WreqClient, EmulationFactory};
use wreq_util::{Emulation, EmulationOS, EmulationOption};

pub static OKHTTP: LazyLock<WreqClient> = LazyLock::new(build_okhttp);
pub static CRONET: LazyLock<WreqClient> = LazyLock::new(build_cronet);

// OkHttp's MODERN_TLS suites in the order Android's Conscrypt offers them.
const OKHTTP_CIPHERS: &str = concat!(
	"TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:",
	"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
	"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
	"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
	"ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
	"AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
);
const OKHTTP_SIGALGS: &str = concat!(
	"ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:",
	"ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:",
	"rsa_pss_rsae_sha512:rsa_pkcs1_sha512:rsa_pkcs1_sha1",
);
// BoringSSL's fixed extension order, as Conscrypt sends it (no GREASE, no permutation).
const OKHTTP_EXTENSIONS: &[ExtensionType] = &[
	ExtensionType::SERVER_NAME,
	ExtensionType::EXTENDED_MASTER_SECRET,
	ExtensionType::RENEGOTIATE,
	ExtensionType::SUPPORTED_GROUPS,
	ExtensionType::EC_POINT_FORMATS,
	ExtensionType::SESSION_TICKET,
	ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
	ExtensionType::STATUS_REQUEST,
	ExtensionType::SIGNATURE_ALGORITHMS,
	ExtensionType::CERTIFICATE_TIMESTAMP,
	ExtensionType::KEY_SHARE,
	ExtensionType::PSK_KEY_EXCHANGE_MODES,
	ExtensionType::SUPPORTED_VERSIONS,
	ExtensionType::PADDING,
];
/// OkHttp's stream and connection windows.
const OKHTTP_WINDOW: u32 = 16 * 1024 * 1024;

/// The ClientHello of OkHttp on Android: Conscrypt (BoringSSL) with OkHttp's MODERN_TLS suites,
/// asking for OCSP and SCTs (the app's network security config turns Certificate Transparency on
/// for reddit.com). wafer also pins one X25519 key share; wreq has no key-shares option, and
/// BoringSSL's default with this curve list sends exactly that one share.
fn okhttp_tls() -> TlsOptions {
	TlsOptions::builder()
		.cipher_list(OKHTTP_CIPHERS)
		.sigalgs_list(OKHTTP_SIGALGS)
		.curves_list("X25519:P-256:P-384")
		.min_tls_version(TlsVersion::TLS_1_2)
		.max_tls_version(TlsVersion::TLS_1_3)
		.alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
		.enable_ocsp_stapling(true)
		.enable_signed_cert_timestamps(true)
		.grease_enabled(false)
		.permute_extensions(false)
		.preserve_tls13_cipher_list(true)
		.extension_permutation(OKHTTP_EXTENSIONS)
		.build()
}

/// OkHttp's HTTP/2: one SETTINGS entry (a 16 MiB stream window), the connection window raised to
/// 16 MiB, pseudo-headers in m, p, a, s order.
fn okhttp_http2() -> Http2Options {
	Http2Options::builder()
		.initial_window_size(OKHTTP_WINDOW)
		.initial_connection_window_size(OKHTTP_WINDOW)
		.settings_order(SettingsOrder::builder().push(SettingId::InitialWindowSize).build())
		.headers_pseudo_order(
			PseudoOrder::builder()
				.extend([PseudoId::Method, PseudoId::Path, PseudoId::Authority, PseudoId::Scheme])
				.build(),
		)
		.build()
}

fn build_okhttp() -> WreqClient {
	info!("Building the OkHttp transport (mint, REST, media)");
	WreqClient::builder()
		.tls_options(okhttp_tls())
		.http2_options(okhttp_http2())
		.redirect(Policy::none())
		.build()
		.expect("Should always be able to build a client")
}

/// The app's GraphQL client: its embedded Cronet sends Chrome 143's ClientHello and HTTP/2. The
/// major follows the app's `libcronet.<version>.so`, not the newest Chrome: bump it with the app.
/// `skip_headers`: Cronet adds no browser headers (no sec-ch-ua, no sec-fetch-*); the app sets its own.
fn build_cronet() -> WreqClient {
	info!("Building the Cronet transport (GraphQL)");
	let emulation = EmulationOption::builder()
		.emulation(Emulation::Chrome143)
		.emulation_os(EmulationOS::Android)
		.skip_headers(true)
		.build()
		.emulation();
	WreqClient::builder()
		.emulation(emulation)
		.redirect(Policy::none())
		.build()
		.expect("Should always be able to build a client")
}
