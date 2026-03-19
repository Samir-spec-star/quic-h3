use bytes::Bytes;
use super::qpack::Header;
/// HTTP Status Code
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode(u16);
impl StatusCode {
    pub const OK: Self = Self(200);
    pub const CREATED: Self = Self(201);
    pub const NO_CONTENT: Self = Self(204);
    pub const BAD_REQUEST: Self = Self(400);
    pub const UNAUTHORIZED: Self = Self(401);
    pub const FORBIDDEN: Self = Self(403);
    pub const NOT_FOUND: Self = Self(404);
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    pub fn new(code: u16) -> Self {
        Self(code)
    }
    pub fn as_u16(&self) -> u16 {
        self.0
    }
    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
    pub fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 < 300
    }
    pub fn is_error(&self) -> bool {
        self.0 >= 400
    }
}
/// An HTTP/3 Response
#[derive(Debug, Clone)]
pub struct Response {
    /// Status code
    pub status: StatusCode,
    /// Response headers
    pub headers: Vec<Header>,
    /// Response body
    pub body: Bytes,
}
impl Response {
    /// Create a new response with a status code
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }
    /// Create a 200 OK response
    pub fn ok() -> Self {
        Self::new(StatusCode::OK)
    }
    /// Create a 404 Not Found response
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND)
            .body_text("Not Found")
    }
    /// Create a 500 Internal Server Error response
    pub fn internal_error() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR)
            .body_text("Internal Server Error")
    }
    /// Add a header
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(Header::new(name, value));
        self
    }
    /// Set body from bytes
    pub fn body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }
    /// Set body from string
    pub fn body_text(mut self, text: &str) -> Self {
        self.headers.push(Header::new("content-type", "text/plain; charset=utf-8"));
        self.headers.push(Header::new("content-length", text.len().to_string()));
        self.body = Bytes::from(text.to_owned());
        self
    }
    /// Set body as JSON
    pub fn body_json(mut self, json: &str) -> Self {
        self.headers.push(Header::new("content-type", "application/json"));
        self.headers.push(Header::new("content-length", &json.len().to_string()));
        self.body = Bytes::from(json.to_owned());
        self
    }
    /// Set body as HTML
    pub fn body_html(mut self, html: &str) -> Self {
        self.headers.push(Header::new("content-type", "text/html; charset=utf-8"));
        self.headers.push(Header::new("content-length", &html.len().to_string()));
        self.body = Bytes::from(html.to_owned());
        self
    }
    /// Convert to QPACK headers
    pub fn to_headers(&self) -> Vec<Header> {
        let mut headers = vec![
            Header::new(":status", &self.status.as_str()),
        ];
        headers.extend(self.headers.clone());
        headers
    }
}
/// Builder for creating responses
pub struct ResponseBuilder {
    response: Response,
}
impl ResponseBuilder {
    pub fn new(status: StatusCode) -> Self {
        Self {
            response: Response::new(status),
        }
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.response = self.response.header(name, value);
        self
    }
    pub fn body(mut self, body: Bytes) -> Self {
        self.response = self.response.body(body);
        self
    }
    pub fn build(self) -> Response {
        self.response
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ok_response() {
        let res = Response::ok()
            .header("server", "quic-h3")
            .body_text("Hello, World!");
        assert_eq!(res.status, StatusCode::OK);
        assert_eq!(&res.body[..], b"Hello, World!");
    }
    #[test]
    fn test_json_response() {
        let res = Response::ok()
            .body_json(r#"{"message": "success"}"#);
        assert!(res.headers.iter().any(|h| h.name == "content-type" && h.value.contains("json")));
    }
    #[test]
    fn test_to_headers() {
        let res = Response::ok()
            .header("x-custom", "value")
            .body_text("test");
        let headers = res.to_headers();
        
        assert!(headers.iter().any(|h| h.name == ":status" && h.value == "200"));
        assert!(headers.iter().any(|h| h.name == "x-custom"));
    }
}
