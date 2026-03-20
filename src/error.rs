use thiserror::Error;

#[derive(Error, Debug)]
pub enum CyberbroError {
    #[error("Invalid observable '{input}': {reason}")]
    ValidationError { input: String, reason: String },

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Analysis timed out after {0}s")]
    Timeout(u64),

    #[error("Unknown engine: '{0}'")]
    UnknownEngine(String),

    #[error("Server error {status}: {body}")]
    ServerError { status: u16, body: String },

    #[error("Config error: {0}")]
    ConfigError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Prompt error: {0}")]
    PromptError(#[from] dialoguer::Error),
}

pub type Result<T> = std::result::Result<T, CyberbroError>;
