use auth_service::utils::constants::JWT_COOKIE_NAME;
use reqwest::Url;

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    app.cookie_jar.add_cookie_str(
        &format!("{JWT_COOKIE_NAME}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/"),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 401);

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;

    let mut response = app
        .create_user_and_login(&get_random_email(), "MySecretPwd", false)
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

    response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;

    let mut response = app
        .create_user_and_login(&get_random_email(), "MySecretPwd", false)
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

    response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);

    response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 400);

    app.cleanup().await;
}
