use crate::helpers::{get_random_email, TestApp};
use auth_service::{
    domain::{Email, LoginAttemptId},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
};
use serde_json::json;

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;

    let response = app
        .post_login(&json!({
            "definitely malformed credetials": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 422);

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let response = app
        .post_login(&json!({
            "email": "invalidemail",
            "password": "pwd"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 400);

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let mut app = TestApp::new().await;

    let response = app
        .post_login(&json!({
            "email": "user@email",
            "password": "definitely_wrong_password"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .create_user_and_login(&random_email, "MySecretPwd", false)
        .await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .create_user_and_login(&random_email, "MySecretPwd", true)
        .await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    assert_eq!(
        app.two_fa_code_store
            .read()
            .await
            .get_code(&Email::parse(&random_email).unwrap())
            .await
            .unwrap()
            .0,
        LoginAttemptId::parse(json_body.login_attempt_id).unwrap()
    );

    app.cleanup().await;
}
