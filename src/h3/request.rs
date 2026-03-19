use super::qpack::Header;
use crate::Result;
use bytes::Bytes;

//HTTP Method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
            Method::Patch => "PATCH",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "GET" => Some(Method::Get),
            "POST" => Some(Method::Post),
            "PUT" => Some(Method::Put),
            "DELETE" => Some(Method::Delete),
            "HEAD" => Some(Method::Head),
            "OPTIONS" => Some(Method::Options),
            "PATCH" => Some(Method::Patch),
            _ => None,
        }
    }
}

//an http/3 request
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method
    pub method: Method,
    /// Request path (e.g., "/api/users")
    pub path: String,
    /// Scheme (http or https)
    pub scheme: String,
    /// Authority (host:port)
    pub authority: String,
    /// Additional headers
    pub headers: Vec<Header>,
    /// Request body (if any)
    pub body: Option<Bytes>,
}
impl Request {
    pub fn get(path: &str) -> Self {
        Self {
            method: Method::Get,
            path: path.to_string(),
            scheme: "https".to_string(),
            authority: "".to_string(),
            headers: Vec::new(),
            body: None,
        }
    }

    //create a new POST request
    pub fn post(path: &str, body: Bytes) -> Self {
        Self {
            method: Method::Post,
            path: path.to_string(),
            scheme: "https".to_string(),
            authority: "".to_string(),
            headers: Vec::new(),
            body: Some(body),
        }
    }

    //set authority
    pub fn authority(mut self, authority: &str) -> Self {
        self.authority = authority.to_string();
        self
    }

    //add a header
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(Header::new(name, value));
        self
    }

    //parse request from decoded headers
    pub fn from_headers(headers: Vec<Header>, body: Option<Bytes>) -> Result<Self> {
        let mut method = Method::Get;
        let mut path = "/".to_string();
        let mut scheme = "https".to_string();
        let mut authority = String::new();
        let mut other_headers = Vec::new();

        for header in headers {
            match header.name.as_str() {
                ":method" => {
                    method = Method::from_str(&header.value).unwrap_or(Method::Get);
                }
                ":path" => path = header.value,
                ":scheme" => {
                    scheme = header.value;
                }
                ":authority" => {
                    authority = header.value;
                }
                _ => {
                    if !header.name.starts_with(':') {
                        other_headers.push(header);
                    }
                }
            }
        }

        Ok(Self {
            method,
            path,
            scheme,
            authority,
            headers: other_headers,
            body,
        })
    }

    //convert to QPACK headers
    pub fn to_headers(&self) -> Vec<Header> {
        let mut headers = vec![
            Header::new(":method", self.method.as_str()),
            Header::new(":scheme", &self.scheme),
            Header::new(":authority", &self.authority),
            Header::new(":path", &self.path),
        ];
        headers.extend(self.headers.clone());
        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_get_request() {
        let req = Request::get("/api/users")
            .authority("example.com")
            .header("accept", "application/json");
        assert_eq!(req.method, Method::Get);
        assert_eq!(req.path, "/api/users");
        assert_eq!(req.authority, "example.com");
    }
    #[test]
    fn test_from_headers() {
        let headers = vec![
            Header::new(":method", "POST"),
            Header::new(":path", "/submit"),
            Header::new(":scheme", "https"),
            Header::new(":authority", "api.example.com"),
            Header::new("content-type", "application/json"),
        ];
        let req = Request::from_headers(headers, None).unwrap();

        assert_eq!(req.method, Method::Post);
        assert_eq!(req.path, "/submit");
        assert_eq!(req.headers.len(), 1);
    }
}
