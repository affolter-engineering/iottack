use thiserror::Error;

#[derive(Debug, Error)]
pub enum FrameworkError {
    #[error("plugin error: {0}")]
    Plugin(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("timeout")]
    Timeout,

    #[error("not implemented")]
    NotImplemented,
}
