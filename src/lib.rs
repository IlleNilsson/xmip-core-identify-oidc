#![forbid(unsafe_code)]

//! Identify by oidc: an `OpenID Connect` ID token's subject and issuer, read
//! and not verified.
//!
//! OIDC Core 1.0 section 2 makes an ID token a JWT whose `iss`, `sub` and
//! `aud` are required, and section 5.7 fixes the pair `iss` and `sub` as the
//! only stable identity of the end user. This identifier reads that pair and
//! calls the subject the claim: the issuer rides beside it as evidence, so do
//! the audiences, and the token itself rides as proof for `authenticate/oidc`
//! to check against the issuer's published keys and the nonce. Nothing here
//! checks any of it.
//!
//! The token arrives in the `Authorization` header under `Bearer`, or in
//! whichever property the configuration names — `http.form.id_token` for the
//! `form_post` response mode, once the HTTP transport promotes form fields.
//! A bearer value that is not a compact JWT is an opaque token and `bearer`'s
//! business; a JWT that names no issuer is not an ID token, and saying so is
//! this leaf's job rather than presenting half a name.
//!
//! What this reads and writes:
//!
//! ```text
//! http.header.authorization   Bearer <id token>     the property, by default
//! oidc.issuer                 the iss claim         evidence
//! oidc.audience               the aud claim(s)      evidence, space-separated
//! oidc.token                  the compact token     proof
//! ```
//!
//! Only a pushed arrival carries a passed claim; where Xmip fetched the
//! Stream the token in play was Xmip's own.

use identify::jwt::Compact;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use xcore::{Arriving, Mechanism};

/// The property read by default: the HTTP `Authorization` header.
pub const AUTHORIZATION: &str = "http.header.authorization";
/// The evidence name carrying the issuer.
pub const ISSUER: &str = "oidc.issuer";
/// The evidence name carrying the audiences.
pub const AUDIENCE: &str = "oidc.audience";
/// The proof name the compact token rides under.
pub const TOKEN_PROOF: &str = "oidc.token";

/// Reads an ID token's subject and issuer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Oidc {
    property: String,
    scheme: Option<String>,
}

impl Oidc {
    /// The token under `Bearer` in the `Authorization` header.
    #[must_use]
    pub fn bearer() -> Self {
        Self {
            property: AUTHORIZATION.to_string(),
            scheme: Some("Bearer".to_string()),
        }
    }

    /// The bare token in a named property.
    #[must_use]
    pub fn in_property(property: impl Into<String>) -> Self {
        Self {
            property: property.into(),
            scheme: None,
        }
    }

    fn token<'a>(&self, raw: &'a str) -> Option<&'a str> {
        let raw = raw.trim();
        let token = match &self.scheme {
            Some(scheme) => {
                let (found, rest) = raw.split_once(char::is_whitespace)?;
                if !found.eq_ignore_ascii_case(scheme) {
                    return None;
                }
                rest.trim()
            }
            None => raw,
        };
        is_compact(token).then_some(token)
    }

    fn present(&self, token: &str) -> Result<Presented, IdentifyError> {
        let compact = Compact::parse(token)?;
        let Some(issuer) = compact.claim("iss") else {
            return Err(IdentifyError::new(
                "the ID token names no issuer: no `iss` claim",
            ));
        };
        let Some(subject) = compact.claim("sub") else {
            return Err(IdentifyError::new(
                "the ID token names no subject: no `sub` claim",
            ));
        };

        let mut claim = Presented::passed(self.mechanism(), subject).with_evidence(ISSUER, issuer);
        let audiences = compact.strings_claim("aud");
        if !audiences.is_empty() {
            claim = claim.with_evidence(AUDIENCE, audiences.join(" "));
        }
        Ok(claim.with_proof(TOKEN_PROOF, token))
    }
}

/// Three parts around two dots and no whitespace: the shape RFC 7515 gives a
/// compact serialization, and the test that tells a JWT from an opaque token.
fn is_compact(token: &str) -> bool {
    token.split('.').count() == 3 && !token.contains(char::is_whitespace) && !token.is_empty()
}

impl TransportIdentifier for Oidc {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::oidc()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }
        match arrival
            .property(&self.property)
            .and_then(|raw| self.token(raw))
        {
            Some(token) => self.present(token).map(Some),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    fn token(claims: &str) -> String {
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"k1"}"#),
            URL_SAFE_NO_PAD.encode(claims),
            URL_SAFE_NO_PAD.encode(b"signature")
        )
    }

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn authorization(value: &str) -> Vec<(String, String)> {
        vec![(AUTHORIZATION.to_string(), value.to_string())]
    }

    #[test]
    fn an_id_token_is_presented_by_its_subject_with_issuer_and_audience_beside() {
        let stream = stream();
        let minted = token(concat!(
            r#"{"iss":"https://idp.example","sub":"248289761001","#,
            r#""aud":["orders","billing"],"nonce":"n-0S6"}"#,
        ));
        let properties = authorization(&format!("Bearer {minted}"));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Oidc::bearer()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "248289761001");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.mechanism.name(), "oidc");
        assert_eq!(
            claim.evidence,
            vec![
                (ISSUER.to_string(), "https://idp.example".to_string()),
                (AUDIENCE.to_string(), "orders billing".to_string()),
            ]
        );
        assert_eq!(claim.proof(TOKEN_PROOF), Some(minted.as_str()));
    }

    #[test]
    fn an_opaque_bearer_token_presents_nothing() {
        let stream = stream();
        let properties = authorization("Bearer 2YotnFZFEjr1zCsicMWpAA");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        assert!(Oidc::bearer().identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn an_arrival_without_the_header_presents_nothing() {
        let stream = stream();
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &[]);

        assert!(Oidc::bearer().identify(&arrival).expect("read").is_none());
    }

    #[test]
    fn a_token_without_an_issuer_is_not_an_id_token_and_the_error_says_so() {
        let stream = stream();
        let properties = authorization(&format!("Bearer {}", token(r#"{"sub":"partner-x"}"#)));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure = Oidc::bearer().identify(&arrival).expect_err("no issuer");

        assert!(failure.message.contains("no `iss` claim"), "{failure}");
    }

    #[test]
    fn a_token_that_does_not_decode_is_an_error_naming_why() {
        let stream = stream();
        let properties = authorization("Bearer aQ.b!!.aQ");
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let failure = Oidc::bearer()
            .identify(&arrival)
            .expect_err("not base64url");

        assert!(failure.message.contains("base64url"), "{failure}");
    }

    #[test]
    fn a_configured_property_carries_the_bare_token() {
        let stream = stream();
        let minted = token(r#"{"iss":"https://idp.example","sub":"partner-x","aud":"orders"}"#);
        let properties = [("http.form.id_token".to_string(), minted)];
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://x/in", &properties);

        let claim = Oidc::in_property("http.form.id_token")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(
            claim.evidence[1],
            (AUDIENCE.to_string(), "orders".to_string())
        );
    }

    #[test]
    fn a_scheduled_pickup_presents_nothing_because_the_token_was_xmips_own() {
        let stream = stream();
        let minted = token(r#"{"iss":"https://idp.example","sub":"xmip"}"#);
        let properties = authorization(&format!("Bearer {minted}"));
        let arrival =
            StreamArrival::new(&stream, Arriving::Scheduled, "https://api/out", &properties);

        assert!(Oidc::bearer().identify(&arrival).expect("read").is_none());
    }
}
