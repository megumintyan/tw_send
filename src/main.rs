#![allow(dead_code)]
#![allow(unused_variables)]

use std::error::Error;
use std::fs;
use std::time::SystemTime;
use std::path::Path;
use std::env;

use oauth2::{
    AuthorizationCode,
    AuthUrl,
    ClientId,
    ClientSecret,
    CsrfToken,
    PkceCodeChallenge,
    RedirectUrl,
    Scope,
    TokenResponse,
    TokenUrl,
};

use oauth2::reqwest::http_client;
use oauth2::basic::BasicClient;

struct Config {
    client_id: &'static str,
    client_secret: &'static str,
    auth_url: &'static str,
    token_url: &'static str,
    access_token_ttl: u64,
    tokens_file_path: &'static str,
    client: BasicClient
}

impl Config {
    fn get_config() -> Config {
        let client_id = "";
        let client_secret = "";
        let auth_url = "https://twitter.com/i/oauth2/authorize";
        let token_url = "https://api.twitter.com/2/oauth2/token";
        let redirect_url = "http://localhost";
        let access_token_ttl = 7200;
        let tokens_file_path = "tokens.txt";

        let client = BasicClient::new(
            ClientId::new(client_id.to_string()),
            Some(ClientSecret::new(client_secret.to_string())),
            AuthUrl::new(auth_url.to_string()).unwrap(),
            Some(TokenUrl::new(token_url.to_string()).unwrap())
    ).set_redirect_uri(RedirectUrl::new(redirect_url.to_string()).unwrap());
        Config { client_id, client_secret, auth_url, token_url, access_token_ttl, tokens_file_path, client }
    }
}

struct Message {
    message_type: Option<MessageType>,
    text: Option<String>,
    id: Option<String>,
    poll: Option<String>,
    duration: Option<String>,
    api: Api,
}

impl Message {
    fn build(mut args: impl Iterator<Item = String> + ExactSizeIterator) -> Message {
        args.next();
        match args.len() {
            1 => {
                Message {message_type: Some(MessageType::TEXT),
                         text: args.next(),
                         id: None::<String>,
                         poll: None::<String>,
                         duration: None::<String>,
                         api: Api::PostTweets,}
            }
            2 => {
                let message_type = match &args.next().unwrap()[..] {
                    "-d" => None,
                    _ => { eprintln!("wrong arument"); std::process::exit(1) }
                };
                Message { message_type,
                          text: None::<String>,
                          id: args.next(),
                          poll: None::<String>,
                          duration: None::<String>,
                          api: Api::DeleteTweets, }
            }
            3 => {
                let text = args.next();
                let message_type = match &args.next().unwrap()[..] {
                    "-r" => Some(MessageType::REPLY),
                    "-q" => Some(MessageType::QUOTE),
                    _ => { eprintln!("wrong arument"); std::process::exit(1) }
                };
                Message { message_type,
                          text,
                          id: args.next(),
                          poll: None::<String>,
                          duration: None::<String>,
                          api: Api::PostTweets}

            }
            4 => {
                let text = args.next();
                let message_type = match &args.next().unwrap()[..] {
                    "-p" => Some(MessageType::POLL),
                    _ => { eprintln!("wrong arument"); std::process::exit(1) }
                };
                Message { message_type,
                          text,
                          id: None::<String>,
                          poll: args.next(),
                          duration: args.next(),
                          api: Api::PostTweets,}
            }
            _ => {
                eprintln!("error: invalid command");
                std::process::exit(1);
            }
        }

    }

}

impl Tokens {
    fn get_new_tokens (config: &Config) -> Tokens {

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = config.client
            .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
            .add_scope(Scope::new("tweet.read".to_string()))
            .add_scope(Scope::new("tweet.write".to_string()))
            .add_scope(Scope::new("users.read".to_string()))
            .add_scope(Scope::new("offline.access".to_string()))
        // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();

        println!("Browse to: {}", auth_url);
        println!("Enter a code from url");
        let mut code = String::new();
        std::io::stdin()
            .read_line(&mut code)
            .expect("Failed to read line");

        let token_result = config.client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .request(http_client).unwrap();

        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        let access_token = token_result.access_token().secret().clone();
        let refresh_token = token_result.refresh_token().unwrap().secret().clone();

        Tokens { timestamp, access_token, refresh_token }
    }
}

impl Tokens {
    fn refresh_tokens (&mut self, config: &Config) {
        let token_result = config.client
            .exchange_refresh_token(&oauth2::RefreshToken::new(self.refresh_token.to_string()))
            .request(http_client)
            .expect("can't refresh tokens");

        self.timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        self.access_token = token_result.access_token().secret().clone();
        self.refresh_token = token_result.refresh_token().unwrap().secret().clone();
    }
}

impl Message {
    fn do_tweet(&self, access_token: &str) -> oauth2::HttpResponse {
        let body = match self.message_type.as_ref().unwrap() {
            MessageType::TEXT => format!("{{\"text\": \"{}\"}}", self.text.as_ref().unwrap()),
            MessageType::REPLY => format!("{{\"text\": \"{}\", \"reply\": {{\"in_reply_to_tweet_id\": \"{}\"}} }}", self.text.as_ref().unwrap(), self.id.as_ref().unwrap()),
            MessageType::QUOTE => format!("{{\"text\": \"{}\", \"quote_tweet_id\": \"{}\"}}", self.text.as_ref().unwrap(), self.id.as_ref().unwrap()),
            MessageType::POLL => format!("{{\"text\": \"{}\", \"poll\": {{\"options\": [{}], \"duration_minutes\": {} }}}}", self.text.as_ref().unwrap(), self.poll.as_ref().unwrap(), self.duration.as_ref().unwrap()),
        };

        let url = "https://api.twitter.com/2/tweets".to_string();
        request(url, oauth2::http::Method::POST, body, &access_token)
    }

    fn delete(&self, access_token: &str) -> oauth2::HttpResponse {
        let url = format!("{}/{}", "https://api.twitter.com/2/tweets", self.id.as_ref().unwrap());
        request(url, oauth2::http::Method::DELETE, "".to_string(), &access_token)
    }
}

fn request (url: String, method: oauth2::http::Method, body: String, access_token: &str) -> oauth2::HttpResponse {
    let access_token = format!("Bearer {}", access_token);
    let mut headers = oauth2::http::HeaderMap::new();
    headers.insert("Authorization", oauth2::http::HeaderValue::from_str(&access_token).unwrap());
    headers.insert("Content-Type", oauth2::http::HeaderValue::from_str("application/json").unwrap());

    let r = oauth2::reqwest::http_client(oauth2::HttpRequest {
        url: oauth2::url::Url::parse(url.as_str()).unwrap(),
        method,
        headers,
        body: body.into()})
        .unwrap();
    r
}

#[derive(Debug)]
struct Tokens {
    timestamp: u64,
    access_token: String,
    refresh_token: String
}

impl Tokens {
    fn get_from_file(path: &str) -> Result<Tokens, Box<dyn Error>> {
        let content = fs::read_to_string(path).unwrap();
        let mut lines = content.lines();

        let timestamp: u64 = lines.next().unwrap().parse().unwrap();
        let access_token = lines.next().unwrap().to_string();
        let refresh_token = lines.next().unwrap().to_string();

        Ok(Tokens { timestamp, access_token, refresh_token })
    }
}

impl Tokens {
    fn save_into_file(&self, path: &str) {
        let data = format!("{}\n{}\n{}", self.timestamp, self.access_token, self.refresh_token);
        fs::write(path, data).expect("Unable to write file");
    }
}

impl Tokens {
    fn get_tokens(config: &Config) -> Tokens {
        if Path::new(config.tokens_file_path).exists() == true {
            let cur_time = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut tokens = Tokens::get_from_file(config.tokens_file_path).unwrap();
            if cur_time - tokens.timestamp >= config.access_token_ttl {
                println!("Updating tokens…");
                tokens.refresh_tokens(&config);
                tokens.save_into_file(config.tokens_file_path);
            }

            tokens

        } else {
            let tokens = Tokens::get_new_tokens(&config);
            tokens.save_into_file(config.tokens_file_path);
            tokens
        }
    }
}

enum MessageType {
    TEXT,
    REPLY,
    QUOTE,
    POLL,
}

enum Api {
    PostTweets,
    DeleteTweets,
}

fn main() {
    let config = Config::get_config();
    let tokens = Tokens::get_tokens(&config);

    let message = Message::build(env::args());
    let response = match message.api {
        Api::PostTweets => message.do_tweet(&tokens.access_token),
        Api::DeleteTweets => message.delete(&tokens.access_token),
    };

    println!("{} → {}", response.status_code.to_string(), String::from_utf8(response.body).unwrap());
}
