use axum::{extract::Query, response::Html, response::IntoResponse};

/// Query parameters from Enable Banking OAuth redirect.
#[derive(serde::Deserialize)]
pub struct EbCallbackParams {
    pub code: Option<String>,
    pub error: Option<String>,
}

/// Enable Banking OAuth callback handler.
///
/// Called by the bank after user authentication. Returns an HTML page that
/// auto-redirects to the `honmoon://bank-callback` deep link, passing the
/// authorization code (or error) back to the app.
///
/// Registered redirect URL at enablebanking.com:
///   https://sync.honmoon.app/api/v1/oauth/eb-callback
pub async fn eb_callback(Query(params): Query<EbCallbackParams>) -> impl IntoResponse {
    let deep_link = if let Some(code) = &params.code {
        format!("honmoon://bank-callback?code={}", urlencoding::encode(code))
    } else if let Some(error) = &params.error {
        format!(
            "honmoon://bank-callback?error={}",
            urlencoding::encode(error)
        )
    } else {
        "honmoon://bank-callback?error=unknown".to_string()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="0;url={deep_link}">
    <title>Honmoon - Bank Connection</title>
    <style>
        body {{
            font-family: -apple-system, system-ui, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #1a1a2e;
            color: #e0e0e0;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
        }}
        a {{
            color: #7c4dff;
            text-decoration: none;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <p>Redirecting back to Honmoon...</p>
        <p><a href="{deep_link}">Tap here if not redirected automatically</a></p>
    </div>
    <script>window.location.href = "{deep_link}";</script>
</body>
</html>"#
    );

    // Defense-in-depth: code/error are already percent-encoded (injection-safe),
    // but pin a static CSP + deny framing so this reflected HTML can never load
    // external resources or be clickjacked if a content-type ever slipped.
    let headers = [
        (
            "content-security-policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
    ];

    (headers, Html(html))
}
