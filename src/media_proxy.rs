//! The media proxy behind `/img`, `/vid`, `/thumb` and the other media routes in `main.rs`:
//! fetches from Reddit's CDN on the app's OkHttp transport with the install's User-Agent
//! (`app_wire::media_headers`) and strips CDN headers.

use crate::app_wire;
use crate::oauth::oauth_client;
use crate::server::RequestExt;
use crate::transport::OKHTTP;
use crate::upstream_log;
use hyper::{header, Body, Request as HyperRequest, Response as HyperResponse};
use log::{error, warn};
use wreq::Response as WreqResponse;

pub async fn proxy(req: HyperRequest<Body>, format: &str) -> Result<HyperResponse<Body>, String> {
	let mut url = format!("{format}?{}", req.uri().query().unwrap_or_default());

	// For each parameter in request
	for (name, value) in &req.params() {
		// Fill the parameter value in the url
		url = url.replace(&format!("{{{name}}}"), value);
	}

	// First parameter is target URL (mandatory).
	let wreq_uri = wreq::Uri::try_from(url.clone()).map_err(|_| "Couldn't parse URL".to_string())?;

	// Reddit's CDN intermittently drops connections (resets, HTTP/2 GOAWAY) under
	// concurrent load. Without a retry, each such drop renders as a permanently
	// blank image on the page, so retry transport errors and 5xx briefly.
	const MAX_ATTEMPTS: u32 = 3;
	let mut last_err = String::new();

	// The reader's range and conditional headers go upstream; a value that is not visible ASCII
	// (none a browser sends for these) is dropped.
	let forwarded: app_wire::Headers = ["Range", "If-Modified-Since", "Cache-Control"]
		.into_iter()
		.filter_map(|key| Some((key, req.headers().get(key)?.to_str().ok()?.to_string())))
		.collect();

	for attempt in 1..=MAX_ATTEMPTS {
		let headers = app_wire::media_headers(oauth_client().load().user_agent(), forwarded.clone());
		let builder = app_wire::apply(OKHTTP.get(wreq_uri.clone()), headers);

		let in_flight = upstream_log::start(upstream_log::Kind::Media, wreq_uri.host().unwrap_or_default());
		let sent = builder.send().await;
		in_flight.finish(&sent);
		match sent {
			// Retry CDN-side errors; pass the final attempt's response through unmodified.
			Ok(res) if res.status().is_server_error() && attempt < MAX_ATTEMPTS => {
				last_err = format!("upstream returned {}", res.status());
			}
			Ok(mut res) => {
				let headers = res.headers_mut();

				let mut rm = |key: &str| headers.remove(key);

				rm("access-control-expose-headers");
				rm("server");
				rm("vary");
				rm("etag");
				rm("x-cdn");
				rm("x-cdn-client-region");
				rm("x-cdn-name");
				rm("x-cdn-server-region");
				rm("x-reddit-cdn");
				rm("x-reddit-video-features");
				rm("Nel");
				rm("Report-To");

				return Ok(res.into_hyper_response());
			}
			Err(e) => {
				last_err = e.to_string();
			}
		}

		if attempt < MAX_ATTEMPTS {
			warn!("Proxy fetch for {url} failed (attempt {attempt}/{MAX_ATTEMPTS}): {last_err}");
			tokio::time::sleep(std::time::Duration::from_millis(250 * u64::from(attempt))).await;
		}
	}

	error!("Proxy fetch for {url} failed after {MAX_ATTEMPTS} attempts: {last_err}");
	Err(last_err)
}

trait IntoHyperResponse {
	fn into_hyper_response(self) -> HyperResponse<Body>;
}

impl IntoHyperResponse for WreqResponse {
	fn into_hyper_response(self) -> HyperResponse<Body> {
		let status = self.status();
		let version = self.version();

		let mut builder = HyperResponse::builder().status(status.as_u16()).version(match version {
			wreq::Version::HTTP_09 => hyper::Version::HTTP_09,
			wreq::Version::HTTP_10 => hyper::Version::HTTP_10,
			wreq::Version::HTTP_11 => hyper::Version::HTTP_11,
			wreq::Version::HTTP_2 => hyper::Version::HTTP_2,
			wreq::Version::HTTP_3 => hyper::Version::HTTP_3,
			_ => hyper::Version::HTTP_11,
		});

		for (name, value) in self.headers() {
			builder = builder.header(
				header::HeaderName::from_bytes(name.as_str().as_bytes()).unwrap(),
				header::HeaderValue::from_bytes(value.as_bytes()).unwrap(),
			);
		}

		builder.body(Body::wrap_stream(self.bytes_stream())).unwrap()
	}
}
