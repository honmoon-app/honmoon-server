use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub email: String,
    /// "cs" or "en" — decides which language the confirmation mail is in.
    pub lang: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    pub token: String,
}

/// Deliberately loose. Real validation is the confirmation mail arriving;
/// this only keeps obvious junk out of the table.
fn looks_like_email(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 6 || value.len() > 254 || value.contains(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.contains("..")
}

fn normalize_lang(lang: Option<String>) -> String {
    match lang.as_deref() {
        Some(l) if l.to_lowercase().starts_with("cs") => "cs".to_string(),
        _ => "en".to_string(),
    }
}

/// POST /api/v1/newsletter/subscribe
///
/// Always answers `{"ok": true}` for any syntactically valid address, whether
/// it was new, pending or already subscribed. Reporting the difference would
/// turn this into an oracle for "is this person a Honmoon user".
pub async fn subscribe(
    State(state): State<AppState>,
    Json(req): Json<SubscribeRequest>,
) -> impl IntoResponse {
    if !looks_like_email(&req.email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(SubscribeResponse { ok: false }),
        );
    }

    let lang = normalize_lang(req.lang);

    let outcome = match state
        .db
        .subscribe_newsletter(&req.email, &lang, "landing")
        .await
    {
        Ok(o) => o,
        Err(e) => {
            error!("newsletter subscribe failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SubscribeResponse { ok: false }),
            );
        }
    };

    // Never re-mail a confirmed subscriber: the form is public, so that would
    // let anyone use us to nag an address they do not own.
    if !outcome.already_active {
        let link = format!(
            "{}/api/v1/newsletter/confirm?token={}",
            state.mailer.base_url.trim_end_matches('/'),
            outcome.token
        );
        let (subject, text, html) = confirmation_mail(&lang, &link);
        let email = req.email.trim().to_lowercase();
        let mailer = state.mailer.clone();
        // Do not make the visitor wait on the SMTP hop.
        tokio::spawn(async move {
            mailer.send(&email, &subject, text, html).await;
        });
    }

    (StatusCode::OK, Json(SubscribeResponse { ok: true }))
}

/// GET /api/v1/newsletter/confirm?token=…
pub async fn confirm(
    State(state): State<AppState>,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    match state.db.confirm_newsletter(&q.token).await {
        Ok(Some(lang)) => Html(page(
            &lang,
            if lang == "cs" {
                ("Hotovo.", "Odběr novinek je potvrzený. Ozveme se, až bude co říct — a nic jiného vám posílat nebudeme.")
            } else {
                ("Done.", "Your subscription is confirmed. We will write when there is something worth saying, and never for anything else.")
            },
        )),
        Ok(None) => Html(page(
            "en",
            ("Link expired.", "That confirmation link is not valid any more. Subscribe again on honmoon.app and we will send a fresh one."),
        )),
        Err(e) => {
            error!("newsletter confirm failed: {e}");
            Html(page("en", ("Something broke.", "Try the link again in a minute.")))
        }
    }
}

/// GET /api/v1/newsletter/unsubscribe?token=…
///
/// One click, no login, no "are you sure" — the address is out the moment the
/// link is opened. Required by the bulk-sender rules and the right default.
pub async fn unsubscribe(
    State(state): State<AppState>,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    match state.db.unsubscribe_newsletter(&q.token).await {
        Ok(Some(lang)) => Html(page(
            &lang,
            if lang == "cs" {
                ("Odhlášeno.", "Už vám nic neposíláme. Adresu si držíme jen proto, abychom vás omylem nepřidali zpátky.")
            } else {
                ("Unsubscribed.", "Nothing more will be sent. We keep the address only so you do not get added back by accident.")
            },
        )),
        Ok(None) => Html(page(
            "en",
            ("Nothing to do.", "That link is not valid, so there is nothing subscribed to remove."),
        )),
        Err(e) => {
            error!("newsletter unsubscribe failed: {e}");
            Html(page("en", ("Something broke.", "Try the link again in a minute.")))
        }
    }
}

fn confirmation_mail(lang: &str, link: &str) -> (String, String, String) {
    if lang == "cs" {
        (
            "Potvrďte odběr novinek Honmoon".to_string(),
            format!(
                "Někdo (snad vy) přihlásil tuhle adresu k odběru novinek o Honmoonu.\n\n\
                 Potvrďte to prosím tímhle odkazem:\n{link}\n\n\
                 Pokud jste to nebyl(a) vy, nemusíte dělat nic — bez potvrzení vám nic nepřijde."
            ),
            format!(
                "<p>Někdo (snad vy) přihlásil tuhle adresu k odběru novinek o Honmoonu.</p>\
                 <p><a href=\"{link}\">Potvrdit odběr</a></p>\
                 <p style=\"color:#616164;font-size:13px\">Pokud jste to nebyl(a) vy, nemusíte dělat nic — bez potvrzení vám nic nepřijde.</p>"
            ),
        )
    } else {
        (
            "Confirm your Honmoon newsletter".to_string(),
            format!(
                "Someone (hopefully you) signed this address up for news about Honmoon.\n\n\
                 Confirm with this link:\n{link}\n\n\
                 If it was not you, do nothing — without a confirmation we never send anything."
            ),
            format!(
                "<p>Someone (hopefully you) signed this address up for news about Honmoon.</p>\
                 <p><a href=\"{link}\">Confirm the subscription</a></p>\
                 <p style=\"color:#616164;font-size:13px\">If it was not you, do nothing — without a confirmation we never send anything.</p>"
            ),
        )
    }
}

/// A one-off page in the landing page's colours. Not worth a template engine.
fn page(lang: &str, (title, body): (&str, &str)) -> String {
    let _ = lang;
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\">\
         <title>{title} · Honmoon</title>\
         <style>body{{margin:0;min-height:100dvh;display:grid;place-items:center;\
         background:#FBF4E8;color:#453A2C;font-family:system-ui,sans-serif;padding:24px}}\
         main{{max-width:420px;background:#FFFDF6;border:1px solid #E5D8C2;border-radius:4px;\
         padding:32px 28px;box-shadow:0 10px 24px -10px rgba(69,58,44,.25);transform:rotate(-.4deg)}}\
         h1{{font-family:Georgia,serif;font-size:26px;margin:0 0 10px;font-weight:600}}\
         p{{margin:0;line-height:1.6;color:#58585C}}\
         a{{color:#A74A25}}</style></head>\
         <body><main><h1>{title}</h1><p>{body}</p>\
         <p style=\"margin-top:20px\"><a href=\"https://honmoon.app\">honmoon.app</a></p>\
         </main></body></html>"
    )
}

/// Unknown token is not an error the caller can act on, so keep the warning
/// out of the hot path but leave a breadcrumb for support questions.
#[allow(dead_code)]
fn note_unknown_token(token: &str) {
    warn!("newsletter token not found: {}…", &token[..token.len().min(8)]);
}
