use auth_service::utils::constants::JWT_COOKIE_NAME;
use reqwest::Url;

use crate::helpers::TestApp;

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_token(&serde_json::json!({
            "invalid_jwt": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

    let mut response = app
        .create_user_and_login("test@email.com", "MySecretPwd", false)
        .await;

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    let token = auth_cookie.value();

    response = app
        .post_verify_token(&serde_json::json!({
            "token": token
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let response = app
        .post_verify_token(&serde_json::json!({
            "token": "invalid token"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    let response = app
        .create_user_and_login("test@email.com", "MySecretPwd", false)
        .await;

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    // Logged in

    let token = auth_cookie.value();
    app.cookie_jar.add_cookie_str(
        &format!("{JWT_COOKIE_NAME}={token}; HttpOnly; SameSite=Lax; Secure; Path=/"),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app
        .post_verify_token(&serde_json::json!({
            "token": token.to_owned()
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);
}
