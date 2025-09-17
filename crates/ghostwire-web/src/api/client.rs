/// HTTP client configuration and setup

use gloo_net::http::Request;
use crate::types::ApiResponse;

pub struct ApiClient {
    base_url: String,
    token: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            token: None,
        }
    }

    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    pub async fn get<T>(&self, path: &str) -> Result<ApiResponse<T>, String>
    where
        T: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut request = Request::get(&url);

        if let Some(token) = &self.token {
            request = request.header("Authorization", &format!("Bearer {}", token));
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        if response.ok() {
            let data: ApiResponse<T> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            Ok(data)
        } else {
            Err(format!("HTTP error: {}", response.status()))
        }
    }

    pub async fn post<T, R>(&self, path: &str, body: &T) -> Result<ApiResponse<R>, String>
    where
        T: serde::Serialize,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut request = Request::post(&url).json(body).map_err(|e| format!("Failed to serialize body: {}", e))?;

        if let Some(token) = &self.token {
            request = request.header("Authorization", &format!("Bearer {}", token));
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("Network error: {}", e))?;

        if response.ok() {
            let data: ApiResponse<R> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e))?;
            Ok(data)
        } else {
            Err(format!("HTTP error: {}", response.status()))
        }
    }
}