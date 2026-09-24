#[cfg(test)]
mod tests {
    use axum::{extract::Query, http::StatusCode, routing::get, Router};
    use std::{collections::HashMap, thread::self, time::{Duration, Instant}};
    
    use crate::core::*;
    
    fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false
        }

        for (a, b) in a.iter().zip(b) {
            if a != b {
                return false
            }
            thread::sleep(Duration::from_millis(50));
        }

        true
    }
    
    async fn handle_test(Query(params): Query<HashMap<String, String>>) -> StatusCode {
        let file = params["file"].as_bytes();
        let signature = hex_to_bytes(&params["signature"]);
        let hmac = hmac(&DICT_KEY, file, SHA1::digest, 64);
        
        if insecure_compare(&signature, &hmac) {
            StatusCode::OK
        }
        else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
    
    async fn run_server(listener: tokio::net::TcpListener) {
        let app = Router::new().route("/test", get(handle_test));
        axum::serve(listener, app).await.unwrap();
    }
    
    async fn measure_delay(client: &reqwest::Client, url: &str) -> Duration {
        let start = Instant::now();
        let _ = client.get(url).send().await;
        start.elapsed()
    }

    #[tokio::test]
    async fn s04_c31_breaking_hmac_sha1_with_artificial_timing_leak() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(run_server(listener));

        let mut sig = vec![0; 20];

        let client = reqwest::Client::new();

        for i in 0..20 {
            let mut best_delay = Duration::ZERO;
            let mut best_byte = 0;
            
            for byte in 0..=255 {
                sig[i] = byte;
                let url = format!("http://localhost:{port}/test?file=foo&signature={}", bytes_to_hex(&sig));

                let delay = measure_delay(&client, &url).await;

                if delay > best_delay {
                    best_delay = delay;
                    best_byte = byte;
                }
            }

            sig[i] = best_byte;
        }
        
        let url = format!("http://localhost:{port}/test?file=foo&signature={}", bytes_to_hex(&sig));
        let status = reqwest::get(url).await.unwrap().status();
        
        assert_eq!(status, StatusCode::OK);
    }
}