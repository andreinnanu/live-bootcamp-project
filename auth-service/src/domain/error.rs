pub enum AuthAPIError {
    UserAlreadyExists,
    InvalidCredentials,
    UnexpectedError,
    MissingToken,
    InvalidToken,
    IncorrectCredentials
}