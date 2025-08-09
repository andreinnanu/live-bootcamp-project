use auth_service::{
    domain::Email, routes::TwoFactorAuthResponse, utils::constants::JWT_COOKIE_NAME,
};
use serde_json::json;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let response = app
        .post_verify_2fa(&serde_json::json!({
            "definitely invalid body": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;
    let response = app
        .post_verify_2fa(&serde_json::json!({
            "email": "invalidemail",
            "loginAttemptId": "123",
            "2FACode": "12412412"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .create_user_and_login(&random_email, "MySecretPwd", true)
        .await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let response = app
        .post_verify_2fa(&json!({
            "email": random_email,
            "loginAttemptId": json_body.login_attempt_id,
            "2FACode": "111111".to_owned()
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .create_user_and_login(&random_email, "MySecretPwd", true)
        .await;

    assert_eq!(response.status().as_u16(), 206);

    let (_, old_2fa_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(&random_email).unwrap())
        .await
        .unwrap();

    let response = app
        .post_login(&json!({
            "email": random_email,
            "password": "MySecretPwd"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let response = app
        .post_verify_2fa(&json!({
            "email": random_email,
            "loginAttemptId": json_body.login_attempt_id,
            "2FACode": old_2fa_code.as_ref().to_owned()
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .create_user_and_login(&random_email, "MySecretPwd", true)
        .await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let (_, code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(&random_email).unwrap())
        .await
        .unwrap();

    let response = app
        .post_verify_2fa(&json!({
            "email": random_email,
            "loginAttemptId": json_body.login_attempt_id,
            "2FACode": code.as_ref().to_owned()
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200);

    let response = app
        .post_verify_2fa(&json!({
            "email": random_email,
            "loginAttemptId": json_body.login_attempt_id,
            "2FACode": code.as_ref().to_owned()
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    // Make sure to assert the auth cookie gets set
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let response = app
        .create_user_and_login(&random_email, "MySecretPwd", true)
        .await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let (_, code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&Email::parse(&random_email).unwrap())
        .await
        .unwrap();

    let response = app
        .post_verify_2fa(&json!({
            "email": random_email,
            "loginAttemptId": json_body.login_attempt_id,
            "2FACode": code.as_ref().to_owned()
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200);
    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
}
