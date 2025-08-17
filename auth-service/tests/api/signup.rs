use auth_service::{routes::SignupResponse, ErrorResponse};

use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let mut app = TestApp::new().await;
    let response = app
        .post_signup(&serde_json::json!({
            "email": "Test@email.com",
            "password": "password123",
            "requires2FA": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "password": "password1234",
            "email": random_email
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {test_case:?}"
        );
    }

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "1234",
            "requires2FA": true,
            "email": random_email
        }),
        serde_json::json!({
            "password": "password1234",
            "email": "",
            "requires2FA": true,
        }),
        serde_json::json!({
            "password": "password1234",
            "email": "asd",
            "requires2FA": true,
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {test_case:?}"
        );
        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.cleanup().await;
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let mut app = TestApp::new().await;
    let response = app
        .post_signup(&serde_json::json!({
            "email": "Test@email.com",
            "password": "password123",
            "requires2FA": true
        }))
        .await;

    assert_eq!(response.status().as_u16(), 201);

    let second_response = app
        .post_signup(&serde_json::json!({
            "email": "Test@email.com",
            "password": "password123",
            "requires2FA": true
        }))
        .await;
    assert_eq!(second_response.status().as_u16(), 409);

    assert_eq!(
        second_response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );

    app.cleanup().await;
}
