//! Small local CLI: explicit Google login, immutable account state, ASCII text only.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand, ValueEnum};
use fs2::FileExt;
use isyeet_client::{MAX_STATE_BYTES, State};
use isyeet_wire::*;
use rand::{Rng, RngCore, TryRngCore};
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use url::Url;

#[derive(Parser)]
#[command(version, about = "ISYEET: I Send You E2E Text")]
struct Args {
    #[arg(long, env = "ISYEET_SERVER", default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long, env = "ISYEET_STATE", default_value = "isyeet-state.json")]
    state: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Sign in to Gmail or Google Workspace in the browser with an OAuth Desktop client.
    Login {
        #[arg(
            long,
            env = "ISYEET_GOOGLE_CLIENT_ID",
            required_unless_present = "client_config",
            conflicts_with = "client_config"
        )]
        client_id: Option<String>,
        #[arg(
            long,
            env = "ISYEET_GOOGLE_CLIENT_SECRET",
            hide_env_values = true,
            conflicts_with = "client_config"
        )]
        client_secret: Option<String>,
        /// Google's downloaded OAuth Desktop JSON. Token endpoints remain fixed.
        #[arg(long)]
        client_config: Option<PathBuf>,
    },
    /// Local test only; requires a feature-gated development server on loopback.
    DevLogin {
        email: String,
    },
    /// Show your public identity fingerprint to compare over a trusted channel.
    Fingerprint,
    /// Look up a Gmail or Google Workspace contact and pin its immutable public identity.
    AddContact {
        email: String,
    },
    /// Confirm the full fingerprint received independently from the contact.
    VerifyContact {
        email: String,
        #[arg(long)]
        fingerprint: String,
    },
    /// Retired shortcut: remove, re-add and independently verify the contact instead.
    #[command(hide = true)]
    ReplaceContact {
        email: String,
        /// The currently pinned full fingerprint, shown by contacts.
        #[arg(long)]
        previous_fingerprint: String,
        /// The new full fingerprint obtained independently from the contact.
        #[arg(long)]
        fingerprint: String,
    },
    /// Remove a contact, its direct history and all affected unsent messages.
    RemoveContact {
        email: String,
        /// The current full saved fingerprint from contacts; prevents stale removal.
        #[arg(long)]
        previous_fingerprint: String,
    },
    Contacts,
    /// List retained immutable groups and their verified member fingerprints.
    Groups,
    /// Create a group of 2-8 independently verified people, including yourself.
    CreateGroup {
        #[arg(long)]
        title: String,
        #[arg(required = true, num_args = 1..=7)]
        members: Vec<String>,
    },
    /// Show retained local messages; expired messages are deleted before display.
    History,
    /// Send printable ASCII text. Omit --text to read exact bytes from standard input.
    Send {
        email: String,
        #[arg(long)]
        text: Option<String>,
    },
    /// Test encrypted relay delivery to your own account; no local plaintext echo.
    SendSelf {
        #[arg(long)]
        text: Option<String>,
    },
    /// Send to every member using separate Signal sessions; omit --text for stdin.
    SendGroup {
        group_id: String,
        #[arg(long)]
        text: Option<String>,
    },
    /// Retry the durable outbox with the original IDs and ciphertext.
    Retry,
    /// Receive queued messages; persist state and text before acknowledging.
    Receive,
    /// Choose remote notifications or quiet, paced cover traffic (never both).
    TrafficMode {
        mode: TrafficMode,
    },
    /// Show the local cover budget and the account's remote notification policy.
    TrafficStatus,
    /// Run the cover-mode sender and inbox loop. Stop with Ctrl-C; queued text is saved.
    Traffic {
        /// Stop after this many scheduled slots, for a bounded local test.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=10000))]
        slots: Option<u32>,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum TrafficMode {
    Notifications,
    Cover,
}

const MESSAGE_POST_BYTES: usize = 12_288;
const MIN_SLOT_SECONDS: u64 = 15;
const MAX_SLOT_SECONDS: u64 = 45;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TrafficPolicy {
    cover: bool,
    notifications_resume_at: Option<i64>,
    server_time: i64,
}
#[derive(Clone, Serialize, Deserialize)]
struct LocalState {
    server: String,
    token: String,
    expires_at: i64,
    core: State,
    #[serde(default)]
    contact_identity_changes: BTreeSet<String>,
}

impl LocalState {
    fn ensure_contact_ready(&self, email: &str) -> Result<()> {
        ensure!(
            !self.contact_identity_changes.contains(email),
            "Contact identity changed; remove-contact, then add-contact and independently verify the new fingerprint before sending or retrying."
        );
        Ok(())
    }

    fn ensure_group_ready(&self, group_id: &str) -> Result<()> {
        let groups: Vec<isyeet_client::Group> =
            serde_json::from_value(self.core.snapshot()?["groups"].clone())?;
        let group = groups
            .iter()
            .find(|group| group.id == group_id)
            .context("Unknown group.")?;
        ensure!(
            !group.blocked,
            "This group's identity verification changed. Create a new group after re-verifying its members."
        );
        for member in &group.members {
            self.ensure_contact_ready(&member.email)?;
        }
        Ok(())
    }

    fn ensure_outgoing_ready(&self, message: &SendRequest) -> Result<()> {
        self.ensure_contact_ready(&message.recipient)?;
        let refs: Vec<isyeet_client::OutboxRef> =
            serde_json::from_value(self.core.snapshot()?["outbox_refs"].clone())?;
        if let Some(leg) = refs.iter().find(|leg| leg.id == message.id) {
            self.ensure_group_ready(&leg.group_id)?;
        }
        Ok(())
    }
}

fn message_text(text: Option<String>) -> Result<String> {
    let bytes = match text {
        Some(text) => text.into_bytes(),
        None => {
            let mut bytes = Vec::new();
            std::io::stdin().take(1026).read_to_end(&mut bytes)?;
            bytes
        }
    };
    ensure!(
        isyeet_client::valid_text(&bytes),
        "Only 1-1024 printable ASCII bytes are accepted."
    );
    Ok(String::from_utf8(bytes)?)
}

fn loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"))
}
fn server_url(raw: &str) -> Result<String> {
    let url = Url::parse(raw).context("Invalid service URL.")?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "Service URL must contain only scheme, host, and optional port."
    );
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback(&url)),
        "HTTPS is required outside literal loopback development."
    );
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
fn client() -> Result<Client> {
    Ok(Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
fn success(response: Response) -> Result<Response> {
    ensure!(
        response.status().is_success(),
        "Service rejected the request (HTTP {}).",
        response.status().as_u16()
    );
    Ok(response)
}
fn json_response<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    let response = success(response)?;
    let mut bytes = Vec::new();
    response.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 2 * 1024 * 1024,
        "Service response too large."
    );
    serde_json::from_slice(&bytes).context("Invalid service response.")
}
fn safe_file(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("Cannot open private state file.")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "State and lock must be private regular files owned by this user (mode 0600)."
    );
    Ok(file)
}
fn lock_state(path: &Path) -> Result<File> {
    let lock_path = path.with_extension("lock");
    let lock = safe_file(&lock_path, true)?;
    lock.try_lock_exclusive()
        .context("Another ISYEET process is using this account.")?;
    Ok(lock)
}
fn load(path: &Path) -> Result<Option<LocalState>> {
    let mut file = match safe_file(path, false) {
        Ok(file) => file,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    ensure!(
        file.metadata()?.len() <= MAX_STATE_BYTES as u64,
        "State file too large."
    );
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    let state: LocalState =
        serde_json::from_slice(&data).context("Invalid state file; refusing to replace keys.")?;
    ensure!(
        state.contact_identity_changes.len() <= 64
            && state.contact_identity_changes.iter().all(|email| {
                canonical_email(email).as_ref() == Ok(email) && state.core.has_contact(email)
            }),
        "Invalid state file; refusing to replace keys."
    );
    Ok(Some(state))
}
fn save(path: &Path, state: &LocalState) -> Result<()> {
    let data = serde_json::to_vec(state)?;
    ensure!(data.len() <= MAX_STATE_BYTES, "State capacity reached.");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = parent.join(format!(".isyeet-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        file.write_all(&data)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result.context("Could not durably save state; no send or acknowledgment performed.")
}
fn persist(path: &Path, current: &mut LocalState, mut proposed: LocalState) -> Result<()> {
    proposed.core.expire()?;
    save(path, &proposed)?;
    *current = proposed;
    Ok(())
}
fn expire_state(path: &Path, state: &mut LocalState) -> Result<()> {
    let mut proposed = state.clone();
    if proposed.core.expire()? {
        persist(path, state, proposed)?;
    }
    Ok(())
}
fn remove_local_contact(
    path: &Path,
    state: &mut LocalState,
    email: &str,
    previous_fingerprint: &str,
) -> Result<()> {
    let mut proposed = state.clone();
    if proposed.contact_identity_changes.contains(email) {
        proposed.core.block_groups_for_contact(email)?;
    }
    proposed.core.remove_contact(email, previous_fingerprint)?;
    proposed.contact_identity_changes.remove(email);
    persist(path, state, proposed)
}
fn reconcile_group_identity_warnings(path: &Path, state: &mut LocalState) -> Result<()> {
    if !state.contact_identity_changes.is_empty() {
        let mut proposed = state.clone();
        for email in &proposed.contact_identity_changes {
            proposed.core.block_groups_for_contact(email)?;
        }
        persist(path, state, proposed)?;
    }
    Ok(())
}
fn block_changed_contact(path: &Path, state: &mut LocalState, email: &str) -> Result<()> {
    ensure!(
        state.core.has_contact(email),
        "Unknown contact identity change."
    );
    if !state.contact_identity_changes.contains(email) {
        ensure!(
            state.contact_identity_changes.len() < 64,
            "Contact capacity reached."
        );
        let mut proposed = state.clone();
        proposed.contact_identity_changes.insert(email.to_owned());
        proposed.core.block_groups_for_contact(email)?;
        persist(path, state, proposed)?;
    }
    Ok(())
}
fn random_token() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.unwrap_err().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn desktop_config(path: &Path) -> Result<(String, Option<String>)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("Cannot read OAuth client configuration.")?;
    ensure!(
        file.metadata()?.is_file(),
        "OAuth client configuration must be a regular file."
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 65536,
        "OAuth client configuration too large."
    );
    let data: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Invalid OAuth client configuration JSON."))?;
    let installed = data.get("installed").ok_or_else(|| {
        anyhow::anyhow!(
            "Download a Google Desktop OAuth client configuration, not a Web or iOS client."
        )
    })?;
    let id = installed
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Desktop configuration has no client ID."))?;
    let secret = installed.get("client_secret").and_then(Value::as_str);
    ensure!(
        secret.is_none_or(|s| s.len() <= 4096 && s.is_ascii()),
        "Invalid client configuration."
    );
    Ok((id.to_owned(), secret.map(str::to_owned)))
}
struct GoogleIdentity {
    token: String,
    email: String,
}

fn google_identity_email(token: &str, client_id: &str, nonce: &str, now: i64) -> Result<String> {
    const INVALID: &str = "Google identity response rejected.";
    #[derive(Deserialize)]
    struct Header {
        alg: String,
    }
    #[derive(Deserialize)]
    struct Claims {
        nonce: String,
        iss: String,
        aud: String,
        exp: i64,
        email: String,
        email_verified: bool,
        #[serde(default)]
        hd: Option<String>,
    }
    ensure!(token.len() <= 16384 && token.is_ascii(), INVALID);
    let parts: Vec<_> = token.split('.').collect();
    ensure!(
        parts.len() == 3 && parts.iter().all(|part| !part.is_empty()),
        INVALID
    );
    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| anyhow::anyhow!(INVALID))?;
    let header: Header = serde_json::from_slice(&header).map_err(|_| anyhow::anyhow!(INVALID))?;
    ensure!(header.alg == "RS256", INVALID);
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| anyhow::anyhow!(INVALID))?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| anyhow::anyhow!(INVALID))?;
    let nonce_matches = claims.nonce.len() == nonce.len()
        && claims
            .nonce
            .bytes()
            .zip(nonce.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0;
    ensure!(
        nonce_matches
            && matches!(
                claims.iss.as_str(),
                "accounts.google.com" | "https://accounts.google.com"
            )
            && claims.aud == client_id
            && claims.exp > now,
        INVALID
    );
    google_account_email(&claims.email, claims.email_verified, claims.hd.as_deref())
        .map_err(|_| anyhow::anyhow!(INVALID))
}

fn bind_login_email(login: &LoginResponse, expected: &str) -> Result<()> {
    ensure!(
        login.email == expected,
        "Service account does not match the authenticated Google identity; no local account changes were saved."
    );
    Ok(())
}

fn google_login(
    client: &Client,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<GoogleIdentity> {
    ensure!(
        client_id.ends_with(".apps.googleusercontent.com")
            && client_id.is_ascii()
            && client_id.len() < 256,
        "A Google OAuth Desktop client ID is required."
    );
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let redirect = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );
    let verifier = random_token();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_token();
    let nonce = random_token();
    let mut auth = Url::parse("https://accounts.google.com/o/oauth2/v2/auth")?;
    auth.query_pairs_mut().extend_pairs([
        ("client_id", client_id),
        ("redirect_uri", &redirect),
        ("response_type", "code"),
        ("scope", "openid email"),
        ("state", &state),
        ("nonce", &nonce),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
        ("prompt", "select_account"),
    ]);
    eprintln!("Complete Google sign-in in your browser. If it did not open, visit:\n{auth}");
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open")
        .arg(auth.as_str())
        .spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open")
        .arg(auth.as_str())
        .spawn();
    let start = Instant::now();
    let code = loop {
        ensure!(
            start.elapsed() < Duration::from_secs(180),
            "Google sign-in timed out."
        );
        let (mut connection, _) = match listener.accept() {
            Ok(value) => value,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        connection.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut request = Vec::new();
        loop {
            let mut buffer = [0; 1024];
            let count = connection.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") || request.len() >= 8192 {
                break;
            }
        }
        let parsed = (|| -> Result<String> {
            ensure!(request.len() < 8192, "Invalid OAuth callback.");
            let line = std::str::from_utf8(&request)?.lines().next().unwrap_or("");
            let mut parts = line.split_ascii_whitespace();
            ensure!(parts.next() == Some("GET"), "Invalid callback method.");
            let target = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("Invalid callback."))?;
            ensure!(target.starts_with("/callback?"), "Invalid callback path.");
            let url = Url::parse(&format!("http://127.0.0.1{target}"))?;
            let pairs: Vec<_> = url.query_pairs().collect();
            let values: Vec<_> = pairs
                .iter()
                .filter(|(k, _)| k == "state")
                .map(|(_, v)| v.as_ref())
                .collect();
            ensure!(
                values.len() == 1 && values[0] == state,
                "OAuth state mismatch."
            );
            let codes: Vec<_> = pairs
                .iter()
                .filter(|(k, _)| k == "code")
                .map(|(_, v)| v.as_ref())
                .collect();
            ensure!(
                codes.len() == 1 && codes[0].len() <= 4096,
                "Google sign-in declined or invalid callback."
            );
            Ok(codes[0].to_owned())
        })();
        let (status, body) = if parsed.is_ok() {
            ("200 OK", "Sign-in received. Return to the ISYEET terminal.")
        } else {
            ("400 Bad Request", "Invalid sign-in callback.")
        };
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=us-ascii\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let _ = connection.write_all(response.as_bytes());
        if let Ok(code) = parsed {
            break code;
        }
    };
    let mut form = vec![
        ("client_id", client_id),
        ("code", &code),
        ("code_verifier", &verifier),
        ("redirect_uri", &redirect),
        ("grant_type", "authorization_code"),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let tokens: Value = json_response(
        client
            .post("https://oauth2.googleapis.com/token")
            .form(&form)
            .send()
            .context("Google token exchange failed.")?,
    )?;
    let token = tokens
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("Google did not return an identity token."))?;
    // This exact token came from Google's fixed HTTPS endpoint with redirects
    // disabled. Bind its typed public claims to the browser transaction and local
    // account. The backend still verifies the JWT signature before authorizing.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    let email = google_identity_email(token, client_id, &nonce, now)?;
    Ok(GoogleIdentity {
        token: token.to_owned(),
        email,
    })
}
fn bind_existing_login(
    client: &Client,
    state: &mut LocalState,
    login: LoginResponse,
) -> Result<()> {
    ensure!(
        state.core.email == login.email,
        "This state belongs to a different Google account; refusing to replace its identity."
    );
    // Do not save the fresh bearer until the current registration has been
    // checked. Otherwise a failed login could let a later retry republish a
    // retired initial identity into a deleted/recreated account generation.
    let keys: KeyUpload = json_response(
        client
            .get(format!("{}/v1/keys/me", state.server))
            .bearer_auth(&login.token)
            .send()
            .context("Could not verify this device's existing registration.")?,
    )
    .context("Device registration is missing or changed; existing keys were not uploaded.")?;
    let mut proposed = state.clone();
    proposed
        .core
        .validate_registered_keys(&keys)
        .context("Device registration is missing or changed; existing keys were not uploaded.")?;
    if proposed.core.initial_upload_pending() {
        proposed.core.confirm_initial_upload()?;
    }
    proposed.token = login.token;
    proposed.expires_at = login.expires_at;
    *state = proposed;
    Ok(())
}

fn maintain_keys(client: &Client, path: &Path, state: &mut LocalState, force: bool) -> Result<()> {
    expire_state(path, state)?;
    if state.core.initial_upload_pending() {
        // Only a freshly initialized, durably saved identity has this flag.
        // Migrated state can never automatically republish a deleted identity.
        success(
            client
                .put(format!("{}/v1/keys", state.server))
                .bearer_auth(&state.token)
                .json(&state.core.key_upload())
                .send()
                .context(
                    "Initial key registration is pending; its exact private keys remain saved.",
                )?,
        )?;
        let mut proposed = state.clone();
        proposed.core.confirm_initial_upload()?;
        persist(path, state, proposed)?;
    }
    if !force && !state.core.key_maintenance_due()? {
        return Ok(());
    }
    let request = if let Some(pending) = state.core.pending_key_maintenance() {
        Some(pending)
    } else {
        let inventory: KeyMaintenanceState = json_response(
            client
                .get(format!("{}/v1/keys/maintenance", state.server))
                .bearer_auth(&state.token)
                .send()
                .context("Could not check this device's key registration.")?,
        )?;
        let mut proposed = state.clone();
        let request = futures::executor::block_on(proposed.core.prepare_key_maintenance(inventory))
            .context("Key inventory was rejected; no identity or pending keys were replaced.")?;
        // Generated private keys and the exact request become durable FIRST.
        persist(path, state, proposed)?;
        request
    };
    if let Some(request) = request {
        let receipt: KeyMaintenanceResponse = json_response(
            client
                .put(format!("{}/v1/keys/maintenance", state.server))
                .bearer_auth(&state.token)
                .json(&request)
                .send()
                .context("Public key maintenance is pending; retry reuses the saved request.")?,
        )?;
        let mut proposed = state.clone();
        proposed.core.confirm_key_maintenance(receipt)?;
        persist(path, state, proposed)?;
    }
    Ok(())
}

fn sync_contacts(client: &Client, state: &LocalState) -> Result<()> {
    success(
        client
            .put(format!("{}/v1/contacts", state.server))
            .bearer_auth(&state.token)
            .json(&serde_json::json!({"emails": state.core.verified_contacts()}))
            .send()
            .context("Could not publish verified contacts; retry to synchronize.")?,
    )?;
    Ok(())
}
fn padded_message_body(message: &SendRequest) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(message)?;
    ensure!(
        bytes.len() <= MESSAGE_POST_BYTES,
        "Message request exceeds fixed transport size."
    );
    // JSON whitespace changes neither schema nor ciphertext. All message types,
    // recipients and retries use the same HTTP body length, in either mode.
    bytes.resize(MESSAGE_POST_BYTES, b' ');
    Ok(bytes)
}
fn deliver(client: &Client, state: &LocalState, message: &SendRequest) -> Result<u16> {
    Ok(client
        .post(format!("{}/v1/messages", state.server))
        .bearer_auth(&state.token)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(padded_message_body(message)?)
        .send()?
        .status()
        .as_u16())
}
fn traffic_policy(client: &Client, state: &LocalState) -> Result<TrafficPolicy> {
    json_response(
        client
            .get(format!("{}/v1/traffic-mode", state.server))
            .bearer_auth(&state.token)
            .send()?,
    )
}
fn put_traffic_policy(client: &Client, state: &LocalState, cover: bool) -> Result<TrafficPolicy> {
    let policy: TrafficPolicy = json_response(
        client
            .put(format!("{}/v1/traffic-mode", state.server))
            .bearer_auth(&state.token)
            .json(&serde_json::json!({"cover": cover}))
            .send()?,
    )?;
    ensure!(
        policy.cover == cover,
        "Service did not confirm the requested traffic mode."
    );
    ensure!(
        !cover || policy.notifications_resume_at.is_none(),
        "Service did not confirm quiet mode."
    );
    Ok(policy)
}
fn change_traffic_mode(
    client: &Client,
    path: &Path,
    state: &mut LocalState,
    cover: bool,
) -> Result<TrafficPolicy> {
    if cover {
        // Never advertise receive consent until the relay has silenced the whole
        // mailbox. A persistence failure leaves it quiet, which is the safe side.
        let started = Instant::now();
        let policy = put_traffic_policy(client, state, true)?;
        let mut proposed = state.clone();
        proposed.core.set_traffic_mode(true)?;
        proposed
            .core
            .confirm_traffic_quiet(policy.server_time, elapsed_seconds(started)?)?;
        persist(path, state, proposed)?;
        Ok(policy)
    } else {
        // Revoke local consent and cancel pending cover before restoring alerts.
        // The service waits out the last short consent lease and in-flight POST.
        let mut proposed = state.clone();
        proposed.core.set_traffic_mode(false)?;
        persist(path, state, proposed)?;
        put_traffic_policy(client, state, false)
            .context("Cover mode is off locally. The service may still be quiet; retry traffic-mode notifications.")
    }
}
fn elapsed_seconds(started: Instant) -> Result<i64> {
    let elapsed: i64 = started
        .elapsed()
        .as_nanos()
        .div_ceil(1_000_000_000)
        .try_into()?;
    ensure!(
        elapsed <= 60,
        "Quiet-mode confirmation took too long; no scheduled send performed."
    );
    Ok(elapsed)
}
fn confirm_quiet(client: &Client, path: &Path, state: &mut LocalState) -> Result<()> {
    let started = Instant::now();
    let policy = traffic_policy(client, state)?;
    ensure!(
        policy.cover && policy.notifications_resume_at.is_none(),
        "The relay is not quiet; run traffic-mode cover again."
    );
    let mut proposed = state.clone();
    proposed
        .core
        .confirm_traffic_quiet(policy.server_time, elapsed_seconds(started)?)?;
    persist(path, state, proposed)
}
fn flush(client: &Client, path: &Path, state: &mut LocalState) -> Result<()> {
    expire_state(path, state)?;
    if state.core.cover_enabled() {
        println!("Queued. Cover mode sends only on scheduled slots; keep `traffic` running.");
        return Ok(());
    }
    maintain_keys(client, path, state, false)?;
    sync_contacts(client, state)?;
    let connection = state.clone();
    flush_pending(path, state, |message| deliver(client, &connection, message))
}
fn flush_pending(
    path: &Path,
    state: &mut LocalState,
    mut deliver: impl FnMut(&SendRequest) -> Result<u16>,
) -> Result<()> {
    // Reconcile warnings saved by older clients before any retry. A warning for
    // one member invalidates every still-pending leg of its groups.
    reconcile_group_identity_warnings(path, state)?;
    expire_state(path, state)?;
    let mut failed = false;
    // Never regenerate a ciphertext after a timeout or crash; use the committed
    // outbox. One blocked recipient must not starve another recipient's delivery.
    for id in state
        .core
        .outbox
        .iter()
        .map(|m| m.id.clone())
        .collect::<Vec<_>>()
    {
        // A previous network attempt may have taken this entry past its deadline.
        expire_state(path, state)?;
        let Some(message) = state.core.outbox.iter().find(|m| m.id == id).cloned() else {
            continue;
        };
        if state.ensure_outgoing_ready(&message).is_err() {
            eprintln!(
                "Pending message to {}: remove-contact, add-contact and independently verify the changed identity before retrying.",
                message.recipient
            );
            failed = true;
            continue;
        }
        match deliver(&message) {
            Ok(401) => bail!("Sign in again with the same account; pending messages remain saved."),
            Ok(status) if (200..300).contains(&status) => {
                let mut proposed = state.clone();
                proposed.core.sent(&message.id)?;
                // Persistence failure is fatal: do not send any additional envelope.
                persist(path, state, proposed)?;
                println!("Accepted {}", message.id);
            }
            Ok(_) | Err(_) => failed = true,
        }
    }
    ensure!(
        !failed,
        "Some messages could not be delivered; their original ciphertext remains saved for retry."
    );
    Ok(())
}
fn receive(client: &Client, path: &Path, state: &mut LocalState) -> Result<()> {
    sync_contacts(client, state)?;
    let inbox: InboxResponse = json_response(
        client
            .get(format!("{}/v1/messages?limit=50", state.server))
            .bearer_auth(&state.token)
            .send()?,
    )?;
    ensure!(inbox.messages.len() <= 50, "Inbox exceeds limit.");
    for message in inbox.messages {
        let id = message.id.clone();
        let sender = canonical_email(&message.sender).map_err(anyhow::Error::msg)?;
        if state.contact_identity_changes.contains(&sender) {
            eprintln!(
                "Message pending from {sender}: remove-contact, then add-contact and independently verify its new fingerprint."
            );
            continue;
        }
        let mut proposed = state.clone();
        let received = match futures::executor::block_on(proposed.core.decrypt(message)) {
            Ok(message) => message,
            Err(e) if e.to_string() == "contact_verification_required" => {
                eprintln!(
                    "Message pending from {sender}: add and independently verify this contact first."
                );
                continue;
            }
            Err(e) if e.to_string() == "contact_identity_changed" => {
                block_changed_contact(path, state, &sender)?;
                eprintln!(
                    "Message pending from {sender}: its identity changed. Remove the old contact, then add-contact and independently verify its new fingerprint."
                );
                continue;
            }
            Err(_) => bail!("Rejected invalid service message; no acknowledgment sent."),
        };
        persist(path, state, proposed)?;
        expire_state(path, state)?;
        if received.deferred {
            eprintln!(
                "Group message saved privately pending verification: independently add and verify every group member before viewing it. Use history after verification."
            );
        }
        if !received.duplicate
            && !received.expired
            && let Some(live) = state
                .core
                .history()?
                .into_iter()
                .find(|m| m.id == received.id)
        {
            println!("{}", serde_json::to_string(&live)?);
        }
        success(
            client
                .post(format!("{}/v1/messages/ack", state.server))
                .bearer_auth(&state.token)
                .json(&AckRequest { ids: vec![id] })
                .send()
                .context("Acknowledgment failed; safely retry receive.")?,
        )?;
    }
    // Receive/ACK first: consuming private one-time keys can free capacity
    // even if a later replenishment attempt must fail closed.
    maintain_keys(client, path, state, false)
}
fn slot_delay() -> Duration {
    Duration::from_secs(
        rand::rngs::OsRng
            .unwrap_err()
            .random_range(MIN_SLOT_SECONDS..=MAX_SLOT_SECONDS),
    )
}

/// A due slot permits one POST only. Human traffic takes priority over idle
/// cover. This shapes aggregate sending, not the distribution of recipients.
fn send_slot(
    path: &Path,
    state: &mut LocalState,
    mut deliver_one: impl FnMut(&SendRequest) -> Result<u16>,
) -> Result<()> {
    reconcile_group_identity_warnings(path, state)?;
    expire_state(path, state)?;
    ensure!(state.core.cover_enabled(), "Cover mode is off.");
    let cover_ids = state.core.cover_message_ids();
    let pending = state
        .core
        .outbox
        .iter()
        .filter(|message| state.ensure_outgoing_ready(message).is_ok())
        .min_by_key(|message| cover_ids.contains(&message.id))
        .cloned();
    let message = if let Some(message) = pending {
        message
    } else {
        let peers: Vec<_> = state
            .core
            .cover_candidates()
            .into_iter()
            .filter(|email| state.ensure_contact_ready(email).is_ok())
            .collect();
        if peers.is_empty() {
            return Ok(());
        }
        let peer = &peers[rand::rngs::OsRng.unwrap_err().random_range(0..peers.len())];
        let mut proposed = state.clone();
        let message = futures::executor::block_on(proposed.core.create_cover(peer))?;
        persist(path, state, proposed)?;
        message
    };
    // A slow persistence step can pass the message deadline or consent lease.
    // Never release a ciphertext canceled by the very commit that saved it.
    expire_state(path, state)?;
    let Some(message) = state
        .core
        .outbox
        .iter()
        .find(|pending| pending.id == message.id)
        .cloned()
    else {
        return Ok(());
    };
    state.ensure_outgoing_ready(&message)?;
    match deliver_one(&message) {
        Ok(401) => bail!("Sign in again with the same account; pending messages remain saved."),
        Ok(status) if (200..300).contains(&status) => {
            let is_cover = state.core.cover_message_ids().contains(&message.id);
            let mut proposed = state.clone();
            proposed.core.sent(&message.id)?;
            persist(path, state, proposed)?;
            if !is_cover {
                println!("Accepted {}", message.id);
            }
        }
        // The original ID/ciphertext remains durable after a timeout/rejection.
        // Retrying is another scheduled opportunity, never an immediate loop.
        Ok(_) | Err(_) => {
            // One unavailable recipient must not monopolize every later slot.
            // Reordering is local only; the immutable transport bytes survive.
            let mut proposed = state.clone();
            if let Some(index) = proposed
                .core
                .outbox
                .iter()
                .position(|pending| pending.id == message.id)
            {
                let pending = proposed.core.outbox.remove(index);
                proposed.core.outbox.push(pending);
            }
            persist(path, state, proposed)?;
            eprintln!("Send not confirmed; the next slot can retry the saved envelope.")
        }
    }
    Ok(())
}

fn traffic_loop(client: &Client, path: &Path, server: &str, slots: Option<u32>) -> Result<()> {
    // Only one cadence owner, but release the normal state lock between work so
    // another terminal can enqueue text without restarting or accelerating it.
    let scheduler_lock = safe_file(&path.with_extension("traffic.lock"), true)?;
    scheduler_lock
        .try_lock_exclusive()
        .context("A traffic loop is already running for this account.")?;
    {
        let _lock = lock_state(path)?;
        let mut state = load(path)?.context("Run login first.")?;
        ensure!(
            state.server == server,
            "This state is pinned to another service URL."
        );
        reconcile_group_identity_warnings(path, &mut state)?;
        expire_state(path, &mut state)?;
        ensure!(
            state.core.cover_enabled(),
            "Select traffic-mode cover before starting the loop."
        );
        confirm_quiet(client, path, &mut state)?;
    }
    println!(
        "Cover loop active: one opportunity every 15-45 seconds, only while this process runs. Ctrl-C stops it. Other terminals may queue messages using the same state."
    );
    let mut next_slot = Instant::now() + slot_delay();
    let mut next_receive = Instant::now();
    let mut attempted_slots = 0u32;
    loop {
        let now = Instant::now();
        if now < next_slot && now < next_receive {
            std::thread::sleep((next_slot.min(next_receive) - now).min(Duration::from_secs(1)));
            continue;
        }
        let due = now >= next_slot;
        let lock = match lock_state(path) {
            Ok(lock) => lock,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::WouldBlock) =>
            {
                // A long login/receive can skip slots, but cannot accumulate a
                // burst to send when the other command releases the state.
                if due {
                    next_slot = Instant::now() + slot_delay();
                }
                next_receive = Instant::now() + Duration::from_secs(1);
                continue;
            }
            Err(error) => return Err(error),
        };
        let mut state = load(path)?.context("Saved account is unavailable.")?;
        ensure!(
            state.server == server,
            "This state is pinned to another service URL."
        );
        reconcile_group_identity_warnings(path, &mut state)?;
        expire_state(path, &mut state)?;
        if !state.core.cover_enabled() {
            println!("Cover mode is off; traffic loop stopped.");
            return Ok(());
        }
        if due {
            // Every slot obtains the same account-wide policy/time confirmation,
            // before deciding whether its payload will be text or cover.
            confirm_quiet(client, path, &mut state)?;
            let connection = state.clone();
            send_slot(path, &mut state, |message| {
                deliver(client, &connection, message)
            })?;
            attempted_slots += 1;
            // A fresh monotonic interval, including after a slow network call.
            // No clock rollback, refresh or queued message advances this date.
            next_slot = Instant::now() + slot_delay();
            if slots.is_some_and(|limit| attempted_slots >= limit) {
                return Ok(());
            }
        }
        if Instant::now() >= next_receive {
            receive(client, path, &mut state)?;
            next_receive = Instant::now() + Duration::from_secs(5);
            // A stalled inbox operation skips missed slots without catching up.
            if Instant::now() >= next_slot {
                next_slot = Instant::now() + slot_delay();
            }
        }
        drop(lock);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let server = server_url(&args.server)?;
    if let Command::Traffic { slots } = &args.command {
        return traffic_loop(&client()?, &args.state, &server, *slots);
    }
    let _lock = lock_state(&args.state)?;
    let mut existing = load(&args.state)?;
    if let Some(state) = &existing {
        ensure!(
            state.server == server,
            "This state is pinned to another service URL."
        );
    }
    // This applies even to offline commands and expired authentication sessions.
    if let Some(state) = existing.as_mut() {
        reconcile_group_identity_warnings(&args.state, state)?;
        expire_state(&args.state, state)?;
    }
    let client = client()?;
    let login = match &args.command {
        Command::Login {
            client_id,
            client_secret,
            client_config,
        } => {
            let (client_id, client_secret) = match client_config {
                Some(path) => desktop_config(path)?,
                None => (
                    client_id
                        .clone()
                        .context("Google OAuth Desktop client ID required.")?,
                    client_secret.clone(),
                ),
            };
            let identity = google_login(&client, &client_id, client_secret.as_deref())?;
            let login = json_response::<LoginResponse>(
                client
                    .post(format!("{server}/v1/auth/google"))
                    .json(&GoogleLogin {
                        id_token: identity.token,
                    })
                    .send()
                    .context("Service sign-in failed.")?,
            )?;
            bind_login_email(&login, &identity.email)?;
            Some(login)
        }
        Command::DevLogin { email } => {
            ensure!(
                loopback(&Url::parse(&server)?),
                "Development login is restricted to literal loopback."
            );
            let email = canonical_email(email).map_err(anyhow::Error::msg)?;
            Some(json_response::<LoginResponse>(
                client
                    .post(format!("{server}/v1/auth/dev"))
                    .json(&ContactRequest { email })
                    .send()
                    .context("Development sign-in failed.")?,
            )?)
        }
        _ => None,
    };
    if let Some(login) = login {
        ensure!(
            canonical_email(&login.email).map_err(anyhow::Error::msg)? == login.email
                && login.token.is_ascii()
                && login.token.len() <= 4096,
            "Invalid service login response."
        );
        let mut state = if let Some(mut state) = existing {
            bind_existing_login(&client, &mut state, login)?;
            state
        } else {
            LocalState {
                server,
                token: login.token,
                expires_at: login.expires_at,
                core: futures::executor::block_on(State::initialize(&login.email))?,
                contact_identity_changes: Default::default(),
            }
        };
        state.core.expire()?;
        save(&args.state, &state)?;
        maintain_keys(&client, &args.state, &mut state, true)?;
        sync_contacts(&client, &state)?;
        println!("Signed in as {}", state.core.email);
        println!(
            "Your fingerprint: {}",
            state.core.snapshot()?["fingerprint"].as_str().unwrap_or("")
        );
        return Ok(());
    }
    let mut state = existing.take().ok_or_else(|| {
        anyhow::anyhow!("Run login first (or dev-login against a local development server).")
    })?;
    expire_state(&args.state, &mut state)?;
    let command = match args.command {
        Command::SendSelf { text } => Command::Send {
            email: state.core.email.clone(),
            text,
        },
        command => command,
    };
    match command {
        Command::History => println!("{}", serde_json::to_string_pretty(&state.core.history()?)?),
        Command::Fingerprint => println!(
            "{} {}",
            state.core.email,
            state.core.snapshot()?["fingerprint"].as_str().unwrap_or("")
        ),
        Command::Contacts => println!(
            "{}",
            serde_json::to_string_pretty(&state.core.snapshot()?["contacts"])?
        ),
        Command::Groups => println!(
            "{}",
            serde_json::to_string_pretty(&state.core.snapshot()?["groups"])?
        ),
        Command::TrafficMode { mode } => {
            let policy = change_traffic_mode(
                &client,
                &args.state,
                &mut state,
                matches!(mode, TrafficMode::Cover),
            )?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
            if policy.cover {
                println!(
                    "Remote alerts are off. Run `traffic` and exchange real messages with verified contacts also in cover mode to establish fresh consent."
                );
            } else {
                println!(
                    "Cover mode is off. Remote alerts resume at notifications_resume_at after the consent grace period, if APNs is configured."
                );
            }
        }
        Command::TrafficStatus => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "local": state.core.snapshot()?["traffic"],
                    "relay": traffic_policy(&client, &state)?,
                }))?
            );
        }
        Command::CreateGroup { title, members } => {
            let members = members
                .iter()
                .map(|email| canonical_email(email).map_err(anyhow::Error::msg))
                .collect::<Result<Vec<_>>>()?;
            for email in &members {
                state.ensure_contact_ready(email)?;
            }
            let mut proposed = state.clone();
            let group = proposed.core.create_group(&title, &members)?;
            persist(&args.state, &mut state, proposed)?;
            println!("{}", serde_json::to_string_pretty(&group)?);
        }
        Command::AddContact { email } => {
            let email = canonical_email(&email).map_err(anyhow::Error::msg)?;
            let bundle: KeyBundle = json_response(
                client
                    .post(format!("{}/v1/keys/claim", state.server))
                    .bearer_auth(&state.token)
                    .json(&ContactRequest {
                        email: email.clone(),
                    })
                    .send()?,
            )?;
            ensure!(
                bundle.email == email,
                "Contact lookup returned a different identity."
            );
            let mut proposed = state.clone();
            let contact = futures::executor::block_on(proposed.core.add_contact(bundle))?;
            persist(&args.state, &mut state, proposed)?;
            println!("{}", serde_json::to_string_pretty(&contact)?);
            println!(
                "Compare with the contact over an independent trusted channel, then run verify-contact."
            );
        }
        Command::VerifyContact { email, fingerprint } => {
            let mut proposed = state.clone();
            let contact = proposed.core.verify_contact(&email, &fingerprint)?;
            persist(&args.state, &mut state, proposed)?;
            sync_contacts(&client, &state)?;
            println!("Verified {}", contact["email"].as_str().unwrap_or(""));
        }
        Command::ReplaceContact { .. } => {
            bail!(
                "replace-contact is retired. Use remove-contact with the saved --previous-fingerprint, then add-contact and verify-contact with the new fingerprint from an independent trusted channel."
            );
        }
        Command::RemoveContact {
            email,
            previous_fingerprint,
        } => {
            let email = canonical_email(&email).map_err(anyhow::Error::msg)?;
            remove_local_contact(&args.state, &mut state, &email, &previous_fingerprint)?;
            println!(
                "Removed {email} locally; its direct history and affected unsent messages were discarded. Re-add and independently verify before messaging again."
            );
            sync_contacts(&client, &state).context("Removal is already saved. Relay-permission synchronization is pending; run retry or receive when connected, not remove-contact again.")?;
        }
        Command::Send { email, text } => {
            let email = canonical_email(&email).map_err(anyhow::Error::msg)?;
            state.ensure_contact_ready(&email)?;
            let text = message_text(text)?;
            let mut proposed = state.clone();
            futures::executor::block_on(proposed.core.encrypt(&email, &text))?;
            persist(&args.state, &mut state, proposed)?;
            flush(&client, &args.state, &mut state)?;
        }
        Command::SendGroup { group_id, text } => {
            state.ensure_group_ready(&group_id)?;
            let text = message_text(text)?;
            let mut proposed = state.clone();
            futures::executor::block_on(proposed.core.encrypt_group(&group_id, &text))?;
            // The complete fanout, all ratchets and one history row must be
            // committed together before the first recipient HTTP request.
            persist(&args.state, &mut state, proposed)?;
            flush(&client, &args.state, &mut state)?;
        }
        Command::Retry => flush(&client, &args.state, &mut state)?,
        Command::Receive => receive(&client, &args.state, &mut state)?,
        Command::Login { .. }
        | Command::DevLogin { .. }
        | Command::SendSelf { .. }
        | Command::Traffic { .. } => {
            unreachable!("handled above")
        }
    }
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("ISYEET: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_persists_before_permission_sync_and_failed_save_preserves_old_state() {
        let dir = directory();
        let path = dir.join("state");
        let (core, pin) = futures::executor::block_on(async {
            let mut core = State::initialize("test@gmail.com").await.unwrap();
            let peer = State::initialize("peer@gmail.com").await.unwrap();
            let upload = peer.key_upload();
            let pin = peer.snapshot().unwrap()["fingerprint"]
                .as_str()
                .unwrap()
                .to_owned();
            core.add_contact(KeyBundle {
                email: peer.email,
                registration_id: upload.registration_id,
                identity_key: upload.identity_key,
                signed_pre_key: upload.signed_pre_key,
                kyber_pre_key: upload.kyber_pre_key,
                pre_key: upload.pre_keys.first().cloned(),
            })
            .await
            .unwrap();
            core.verify_contact("peer@gmail.com", &pin).unwrap();
            core.encrypt("peer@gmail.com", "cancel pending")
                .await
                .unwrap();
            (core, pin)
        });
        let mut state = LocalState {
            server: "https://example.com".into(),
            token: "token".into(),
            expires_at: 0,
            core,
            contact_identity_changes: BTreeSet::from(["peer@gmail.com".into()]),
        };
        save(&path, &state).unwrap();
        let before = serde_json::to_value(&state).unwrap();
        assert!(
            remove_local_contact(
                &dir.join("absent/state"),
                &mut state,
                "peer@gmail.com",
                &pin
            )
            .is_err()
        );
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
        assert_eq!(
            serde_json::to_value(load(&path).unwrap().unwrap()).unwrap(),
            before
        );
        remove_local_contact(&path, &mut state, "peer@gmail.com", &pin).unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert!(!loaded.core.has_contact("peer@gmail.com"));
        assert!(loaded.contact_identity_changes.is_empty());
        assert!(loaded.core.verified_contacts().is_empty());
        assert!(loaded.core.outbox.is_empty());
        assert!(loaded.core.history().unwrap().is_empty());
        assert_eq!(
            serde_json::to_value(&state).unwrap(),
            serde_json::to_value(&loaded).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&loaded.core).unwrap()["removed_contacts"][0]["unsafe_identity"],
            true
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn test_deadline() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + MESSAGE_LIFETIME_SECONDS
    }
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("isyeet-cli-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    fn identity_fixture(claims: &Value) -> String {
        // These fixtures exercise parsing/binding only; signature verification is
        // separately mandatory in the backend for the token from Google's TLS API.
        format!(
            "{}.{}.c2lnbmF0dXJl",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        )
    }
    fn valid_identity_claims() -> Value {
        serde_json::json!({"nonce":"test-nonce", "iss":"https://accounts.google.com",
            "aud":"desktop.apps.googleusercontent.com", "exp":2000,
            "email":"A.Lice@GMAIL.com", "email_verified":true})
    }
    #[test]
    fn google_identity_binding_uses_typed_verified_gmail_claims() {
        let claims = valid_identity_claims();
        assert_eq!(
            google_identity_email(
                &identity_fixture(&claims),
                "desktop.apps.googleusercontent.com",
                "test-nonce",
                1000
            )
            .unwrap(),
            "alice@gmail.com"
        );
        let mut alternate_issuer = claims;
        alternate_issuer["iss"] = Value::String("accounts.google.com".into());
        assert!(
            google_identity_email(
                &identity_fixture(&alternate_issuer),
                "desktop.apps.googleusercontent.com",
                "test-nonce",
                1000
            )
            .is_ok()
        );
    }
    #[test]
    fn workspace_identity_accepts_primary_and_secondary_email_domains() {
        let mut claims = valid_identity_claims();
        claims["email"] = serde_json::json!("alice.smith@secondary.example");
        for hosted_domain in ["secondary.example", "primary.example"] {
            claims["hd"] = serde_json::json!(hosted_domain);
            assert_eq!(
                google_identity_email(
                    &identity_fixture(&claims),
                    "desktop.apps.googleusercontent.com",
                    "test-nonce",
                    1000,
                )
                .unwrap(),
                "alice.smith@secondary.example"
            );
        }
    }
    #[test]
    fn workspace_identity_requires_typed_verified_hosted_domain_claims() {
        let mut claims = valid_identity_claims();
        claims["email"] = serde_json::json!("DO_NOT_ECHO@secondary.example");
        let rejected = |claims: &Value| {
            assert_eq!(
                google_identity_email(
                    &identity_fixture(claims),
                    "desktop.apps.googleusercontent.com",
                    "test-nonce",
                    1000,
                )
                .unwrap_err()
                .to_string(),
                "Google identity response rejected."
            );
        };
        rejected(&claims);
        for hosted_domain in [
            Value::Null,
            serde_json::json!(""),
            serde_json::json!(true),
            serde_json::json!(123),
            serde_json::json!(["primary.example"]),
            serde_json::json!({"domain": "primary.example"}),
            serde_json::json!("DO_NOT_ECHO.invalid domain"),
            serde_json::json!("https://DO_NOT_ECHO.example"),
        ] {
            claims["hd"] = hosted_domain;
            rejected(&claims);
        }
        claims["hd"] = serde_json::json!("primary.example");
        for verified in [
            serde_json::json!(false),
            serde_json::json!("true"),
            serde_json::json!(1),
            Value::Null,
        ] {
            claims["email_verified"] = verified;
            rejected(&claims);
        }
    }
    #[test]
    fn malformed_or_unbound_google_claims_are_rejected_without_echoing_data() {
        let invalid_fields = [
            ("nonce", serde_json::json!("DO_NOT_ECHO")),
            ("iss", serde_json::json!("https://DO_NOT_ECHO.example")),
            ("iss", serde_json::json!(123)),
            (
                "aud",
                serde_json::json!("DO_NOT_ECHO.apps.googleusercontent.com"),
            ),
            (
                "aud",
                serde_json::json!(["desktop.apps.googleusercontent.com"]),
            ),
            ("exp", serde_json::json!(1000)),
            ("exp", serde_json::json!(0)),
            ("exp", serde_json::json!("2000")),
            ("exp", serde_json::json!(1.5)),
            ("email_verified", serde_json::json!(false)),
            ("email_verified", serde_json::json!("true")),
            ("email_verified", serde_json::json!(1)),
            ("email_verified", Value::Null),
            ("email", serde_json::json!("DO_NOT_ECHO@example.com")),
            ("email", serde_json::json!("alice+DO_NOT_ECHO@gmail.com")),
            ("email", serde_json::json!("alice@gmail.com\nDO_NOT_ECHO")),
            ("email", serde_json::json!(false)),
        ];
        for (key, value) in invalid_fields {
            let mut claims = valid_identity_claims();
            claims[key] = value;
            let error = google_identity_email(
                &identity_fixture(&claims),
                "desktop.apps.googleusercontent.com",
                "test-nonce",
                1000,
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "Google identity response rejected.");
        }
        let mut missing = valid_identity_claims();
        missing.as_object_mut().unwrap().remove("email_verified");
        assert!(
            google_identity_email(
                &identity_fixture(&missing),
                "desktop.apps.googleusercontent.com",
                "test-nonce",
                1000
            )
            .is_err()
        );
        for token in ["DO_NOT_ECHO", "a.b", "a.b.c.d", "a.@@@@.c", "a..c"] {
            assert_eq!(
                google_identity_email(
                    token,
                    "desktop.apps.googleusercontent.com",
                    "test-nonce",
                    1000
                )
                .unwrap_err()
                .to_string(),
                "Google identity response rejected."
            );
        }
        let duplicate = format!("{}.{}.c2ln", URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#), URL_SAFE_NO_PAD.encode(br#"{"nonce":"test-nonce","iss":"accounts.google.com","aud":"desktop.apps.googleusercontent.com","exp":2000,"email":"alice@gmail.com","email_verified":false,"email_verified":true}"#));
        assert!(
            google_identity_email(
                &duplicate,
                "desktop.apps.googleusercontent.com",
                "test-nonce",
                1000
            )
            .is_err()
        );
        let unsigned = format!(
            "{}.{}.c2ln",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid_identity_claims()).unwrap())
        );
        assert!(
            google_identity_email(
                &unsigned,
                "desktop.apps.googleusercontent.com",
                "test-nonce",
                1000
            )
            .is_err()
        );
    }
    #[test]
    fn backend_cannot_replace_the_google_authenticated_local_email() {
        let mut login = LoginResponse {
            token: "DO_NOT_ECHO_TOKEN".into(),
            email: "alice@gmail.com".into(),
            expires_at: 2000,
        };
        assert!(bind_login_email(&login, "alice@gmail.com").is_ok());
        login.email = "DO_NOT_ECHO_OTHER@gmail.com".into();
        let error = bind_login_email(&login, "alice@gmail.com")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("DO_NOT_ECHO"));
        assert!(!error.contains("alice@gmail.com"));
    }
    #[test]
    fn blocked_recipient_does_not_starve_other_pending_messages() {
        let dir = directory();
        let path = dir.join("state");
        let mut core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        let blocked = SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "blocked@gmail.com".into(),
            envelope: "original-ciphertext-1".into(),
            expires_at: test_deadline(),
        };
        let accepted = SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "accepted@gmail.com".into(),
            envelope: "original-ciphertext-2".into(),
            expires_at: test_deadline(),
        };
        core.outbox = vec![blocked.clone(), accepted.clone()];
        let mut state = LocalState {
            server: "https://example.com".into(),
            token: "token".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        let mut attempted = Vec::new();
        let result = flush_pending(&path, &mut state, |message| {
            attempted.push(message.id.clone());
            Ok(if message.id == blocked.id { 403 } else { 202 })
        });
        assert!(result.is_err());
        assert_eq!(attempted, vec![blocked.id.clone(), accepted.id]);
        let persisted = load(&path).unwrap().unwrap();
        assert_eq!(persisted.core.outbox.len(), 1);
        assert_eq!(persisted.core.outbox[0].id, blocked.id);
        assert_eq!(persisted.core.outbox[0].envelope, blocked.envelope);
        assert_eq!(persisted.core.outbox[0].expires_at, blocked.expires_at);
        assert_eq!(state.core.outbox.len(), 1);
        // A subsequent retry uses the same authenticated deadline, ID and bytes.
        flush_pending(&path, &mut state, |message| {
            assert_eq!(message.id, blocked.id);
            assert_eq!(message.envelope, blocked.envelope);
            assert_eq!(message.expires_at, blocked.expires_at);
            Ok(202)
        })
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn authentication_and_persistence_failures_stop_outbox_processing() {
        let dir = directory();
        let path = dir.join("state");
        let mut core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        core.outbox = (0..2)
            .map(|_| SendRequest {
                id: uuid::Uuid::new_v4().to_string(),
                recipient: "other@gmail.com".into(),
                envelope: "ciphertext".into(),
                expires_at: test_deadline(),
            })
            .collect();
        let mut state = LocalState {
            server: "https://example.com".into(),
            token: "token".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        let mut calls = 0;
        assert!(
            flush_pending(&path, &mut state, |_| {
                calls += 1;
                Ok(401)
            })
            .is_err()
        );
        assert_eq!(calls, 1);
        assert_eq!(state.core.outbox.len(), 2);
        calls = 0;
        assert!(
            flush_pending(&dir.join("absent/state"), &mut state, |_| {
                calls += 1;
                Ok(202)
            })
            .is_err()
        );
        assert!(calls <= 1);
        assert_eq!(state.core.outbox.len(), 2);
        assert_eq!(load(&path).unwrap().unwrap().core.outbox.len(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn changed_identity_block_is_durable_and_skips_only_the_affected_recipient() {
        let dir = directory();
        let path = dir.join("state");
        let mut core = futures::executor::block_on(async {
            let mut core = State::initialize("test@gmail.com").await.unwrap();
            let peer = State::initialize("blocked@gmail.com").await.unwrap();
            let upload = peer.key_upload();
            core.add_contact(KeyBundle {
                email: peer.email,
                registration_id: upload.registration_id,
                identity_key: upload.identity_key,
                signed_pre_key: upload.signed_pre_key,
                kyber_pre_key: upload.kyber_pre_key,
                pre_key: upload.pre_keys.first().cloned(),
            })
            .await
            .unwrap();
            core
        });
        let blocked = SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "blocked@gmail.com".into(),
            envelope: "original-old-session-ciphertext".into(),
            expires_at: test_deadline(),
        };
        let other = SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "other@gmail.com".into(),
            envelope: "unaffected-ciphertext".into(),
            expires_at: test_deadline(),
        };
        core.outbox = vec![blocked.clone(), other.clone()];
        let mut state = LocalState {
            server: "https://example.com".into(),
            token: "token".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        let before = serde_json::to_value(&state).unwrap();
        assert!(
            block_changed_contact(&dir.join("absent/state"), &mut state, &blocked.recipient)
                .is_err()
        );
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
        assert!(block_changed_contact(&path, &mut state, "unknown@gmail.com").is_err());
        block_changed_contact(&path, &mut state, &blocked.recipient).unwrap();
        state = load(&path).unwrap().unwrap();
        assert!(state.ensure_contact_ready(&blocked.recipient).is_err());
        assert!(state.ensure_contact_ready(&other.recipient).is_ok());
        let mut attempted = Vec::new();
        assert!(
            flush_pending(&path, &mut state, |message| {
                attempted.push(message.id.clone());
                Ok(202)
            })
            .is_err()
        );
        assert_eq!(attempted, vec![other.id]);
        let persisted = load(&path).unwrap().unwrap();
        assert_eq!(persisted.contact_identity_changes.len(), 1);
        assert!(persisted.ensure_contact_ready(&blocked.recipient).is_err());
        assert_eq!(
            serde_json::to_value(&persisted.core.outbox).unwrap(),
            serde_json::json!([blocked])
        );
        let mut legacy = serde_json::to_value(&persisted).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("contact_identity_changes");
        assert!(
            serde_json::from_value::<LocalState>(legacy)
                .unwrap()
                .contact_identity_changes
                .is_empty()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn group_warning_cancels_every_unsent_leg_before_any_http_and_preserves_partial_counts() {
        let dir = directory();
        let path = dir.join("state");
        let (core, group_id, already_accepted) = futures::executor::block_on(async {
            let mut core = State::initialize("test@gmail.com").await.unwrap();
            for email in ["blocked@gmail.com", "other@gmail.com"] {
                let peer = State::initialize(email).await.unwrap();
                let upload = peer.key_upload();
                let contact = core
                    .add_contact(KeyBundle {
                        email: email.into(),
                        registration_id: upload.registration_id,
                        identity_key: upload.identity_key,
                        signed_pre_key: upload.signed_pre_key,
                        kyber_pre_key: upload.kyber_pre_key,
                        pre_key: upload.pre_keys.first().cloned(),
                    })
                    .await
                    .unwrap();
                core.verify_contact(email, contact["fingerprint"].as_str().unwrap())
                    .unwrap();
            }
            let group = core
                .create_group(
                    "Test",
                    &["blocked@gmail.com".into(), "other@gmail.com".into()],
                )
                .unwrap();
            let first = core
                .encrypt_group(&group.id, "partially accepted")
                .await
                .unwrap();
            let accepted = first
                .iter()
                .find(|leg| leg.recipient == "other@gmail.com")
                .unwrap()
                .id
                .clone();
            core.sent(&accepted).unwrap();
            core.encrypt_group(&group.id, "entirely pending")
                .await
                .unwrap();
            (core, group.id, accepted)
        });
        let mut state = LocalState {
            server: "https://example.com".into(),
            token: "token".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        };
        assert_eq!(state.core.outbox.len(), 3);
        assert!(
            state
                .core
                .outbox
                .iter()
                .all(|leg| leg.id != already_accepted)
        );
        let unrelated = SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "other@gmail.com".into(),
            envelope: "unrelated-direct-envelope".into(),
            expires_at: test_deadline(),
        };
        state.core.outbox.push(unrelated.clone());
        save(&path, &state).unwrap();
        let original = serde_json::to_value(&state).unwrap();
        assert!(
            block_changed_contact(&dir.join("absent/state"), &mut state, "blocked@gmail.com")
                .is_err()
        );
        assert_eq!(serde_json::to_value(&state).unwrap(), original);
        // A legacy sidecar warning is reconciled even if core invalidation was
        // never saved. The unchanged member's group leg is blocked as well.
        state
            .contact_identity_changes
            .insert("blocked@gmail.com".into());
        save(&path, &state).unwrap();
        assert!(state.ensure_group_ready(&group_id).is_err());
        let other_group_leg = state
            .core
            .outbox
            .iter()
            .find(|leg| leg.recipient == "other@gmail.com" && leg.id != unrelated.id)
            .unwrap();
        assert!(state.ensure_outgoing_ready(other_group_leg).is_err());
        let mut attempted = Vec::new();
        flush_pending(&path, &mut state, |leg| {
            let disk = load(&path).unwrap().unwrap();
            assert_eq!(
                disk.core.outbox.len(),
                1,
                "Group cancellation was not durable before HTTP."
            );
            attempted.push(leg.id.clone());
            Ok(202)
        })
        .unwrap();
        assert_eq!(attempted, vec![unrelated.id]);
        let disk = load(&path).unwrap().unwrap();
        assert!(disk.core.outbox.is_empty());
        let history = disk.core.history().unwrap();
        let partial = history
            .iter()
            .find(|msg| msg.text.as_deref() == Some("partially accepted"))
            .unwrap();
        let pending = history
            .iter()
            .find(|msg| msg.text.as_deref() == Some("entirely pending"))
            .unwrap();
        assert_eq!(partial.status.as_deref(), Some("cancelled"));
        assert_eq!(partial.accepted_count, Some(1));
        assert_eq!(pending.status.as_deref(), Some("cancelled"));
        assert_eq!(pending.accepted_count, Some(0));
        assert!(disk.ensure_group_ready(&group_id).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    fn expired_local_state() -> LocalState {
        let mut core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        let expires_at = test_deadline() - MESSAGE_LIFETIME_SECONDS;
        let id = uuid::Uuid::new_v4().to_string();
        core.outbox.push(SendRequest {
            id: id.clone(),
            recipient: "other@gmail.com".into(),
            envelope: "expired-ciphertext".into(),
            expires_at,
        });
        core.messages.push(isyeet_client::LocalMessage {
            id,
            sender: core.email.clone(),
            recipient: "other@gmail.com".into(),
            text: Some("expired-local-text".into()),
            security_alert: None,
            duplicate: false,
            expires_at,
            expired: false,
            group_id: None,
            logical_id: None,
            sent_at: None,
            received_at: None,
            sender_fingerprint: None,
            status: None,
            accepted_count: None,
            recipient_count: None,
            deferred: false,
            cover: false,
        });
        LocalState {
            server: "https://example.com".into(),
            token: "expired-authentication".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        }
    }
    #[test]
    fn offline_expiry_commits_before_history_or_retry_without_authentication() {
        let dir = directory();
        let path = dir.join("state");
        let mut state = expired_local_state();
        let identity = state.core.key_upload().identity_key;
        save(&path, &state).unwrap();
        expire_state(&path, &mut state).unwrap();
        assert!(state.core.history().unwrap().is_empty());
        assert!(state.core.outbox.is_empty());
        let disk = load(&path).unwrap().unwrap();
        assert!(disk.core.messages.is_empty() && disk.core.outbox.is_empty());
        assert_eq!(disk.core.key_upload().identity_key, identity);
        assert_eq!(disk.expires_at, 0);
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains("expired-local-text")
        );
        flush_pending(&path, &mut state, |_| {
            panic!("expired message must never reach transport")
        })
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn failed_expiry_commit_aborts_before_transport_and_adoption() {
        let dir = directory();
        let mut state = expired_local_state();
        let before = serde_json::to_value(&state).unwrap();
        let result = flush_pending(&dir.join("missing/state"), &mut state, |_| {
            panic!("expiry persistence failure must stop transport")
        });
        assert!(result.is_err());
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn private_state_rejects_public_permissions_and_symlinks() {
        let dir = directory();
        let path = dir.join("state");
        let file = safe_file(&path, true).unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(safe_file(&path, false).is_err());
        let link = dir.join("link");
        symlink(&path, &link).unwrap();
        assert!(safe_file(&link, false).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn commit_before_adopt_and_exclusive_account_lock() {
        let dir = directory();
        let path = dir.join("state");
        let first = lock_state(&path).unwrap();
        assert!(lock_state(&path).is_err());
        let core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        let mut state = LocalState {
            server: "https://example.com".into(),
            token: "old".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        let mut proposed = state.clone();
        proposed.token = "new".into();
        assert!(persist(&dir.join("absent/state"), &mut state, proposed.clone()).is_err());
        assert_eq!(state.token, "old");
        assert_eq!(load(&path).unwrap().unwrap().token, "old");
        persist(&path, &mut state, proposed).unwrap();
        assert_eq!(load(&path).unwrap().unwrap().token, "new");
        drop(first);
        assert!(lock_state(&path).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn only_https_or_literal_loopback_services() {
        assert!(server_url("https://example.com").is_ok());
        assert!(server_url("http://127.0.0.1:8080").is_ok());
        assert!(server_url("http://[::1]:8080").is_ok());
        for url in [
            "http://example.com",
            "http://localhost",
            "https://user:pass@example.com",
            "https://example.com?token=secret",
            "https://example.com/api",
        ] {
            assert!(server_url(url).is_err());
        }
    }
    #[test]
    fn every_message_post_has_fixed_size_and_unchanged_semantics() {
        for recipient in [
            "a@gmail.com".to_owned(),
            format!("{}@{}.example", "a".repeat(64), "b".repeat(63)),
        ] {
            let message = SendRequest {
                id: uuid::Uuid::new_v4().to_string(),
                recipient,
                envelope: base64::engine::general_purpose::STANDARD
                    .encode(vec![42; ENVELOPE_BYTES]),
                expires_at: test_deadline(),
            };
            let body = padded_message_body(&message).unwrap();
            assert_eq!(body.len(), MESSAGE_POST_BYTES);
            let decoded: SendRequest = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                serde_json::to_value(decoded).unwrap(),
                serde_json::to_value(&message).unwrap()
            );
            assert_eq!(
                body,
                padded_message_body(&message).unwrap(),
                "Retries must retain the same request bytes."
            );
        }
    }
    #[test]
    fn a_cover_slot_sends_one_envelope_and_an_uncertain_send_keeps_the_original() {
        let dir = directory();
        let path = dir.join("state");
        let mut core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        core.set_traffic_mode(true).unwrap();
        let message = SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "peer@gmail.com".into(),
            envelope: "saved-ciphertext-one".into(),
            expires_at: test_deadline(),
        };
        core.outbox = vec![
            message.clone(),
            SendRequest {
                id: uuid::Uuid::new_v4().to_string(),
                recipient: "other@gmail.com".into(),
                envelope: "saved-ciphertext-two".into(),
                expires_at: test_deadline(),
            },
        ];
        let mut state = LocalState {
            server: "https://example.com".into(),
            token: "token".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        let mut calls = 0;
        send_slot(&path, &mut state, |sent| {
            calls += 1;
            assert_eq!(
                serde_json::to_value(sent).unwrap(),
                serde_json::to_value(&message).unwrap()
            );
            Err(anyhow::anyhow!("simulated uncertain network result"))
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(state.core.outbox.len(), 2);
        assert_eq!(
            load(&path).unwrap().unwrap().core.outbox[1].envelope,
            message.envelope
        );
        send_slot(&path, &mut state, |sent| {
            calls += 1;
            assert_eq!(
                sent.recipient, "other@gmail.com",
                "An unavailable recipient must not monopolize later slots."
            );
            Ok(202)
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(state.core.outbox.len(), 1);
        assert_eq!(load(&path).unwrap().unwrap().core.outbox.len(), 1);
        send_slot(&path, &mut state, |sent| {
            calls += 1;
            assert_eq!(
                serde_json::to_value(sent).unwrap(),
                serde_json::to_value(&message).unwrap()
            );
            Ok(403)
        })
        .unwrap();
        assert_eq!(calls, 3);
        assert_eq!(state.core.outbox.len(), 1);
        send_slot(&path, &mut state, |sent| {
            calls += 1;
            assert_eq!(
                serde_json::to_value(sent).unwrap(),
                serde_json::to_value(&message).unwrap()
            );
            Ok(202)
        })
        .unwrap();
        assert_eq!(calls, 4);
        assert!(state.core.outbox.is_empty());
        assert!(load(&path).unwrap().unwrap().core.outbox.is_empty());
        state.core.set_traffic_mode(false).unwrap();
        assert!(
            send_slot(&path, &mut state, |_| panic!(
                "Disabled mode must not send from a slot"
            ))
            .is_err()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn regular_flush_cannot_bypass_cover_scheduling_even_with_unreachable_service() {
        let dir = directory();
        let path = dir.join("state");
        let mut core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        core.set_traffic_mode(true).unwrap();
        core.outbox.push(SendRequest {
            id: uuid::Uuid::new_v4().to_string(),
            recipient: "peer@gmail.com".into(),
            envelope: "saved-ciphertext".into(),
            expires_at: test_deadline(),
        });
        let mut state = LocalState {
            server: "http://127.0.0.1:1".into(),
            token: "token".into(),
            expires_at: 0,
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        flush(&client().unwrap(), &path, &mut state).unwrap();
        assert_eq!(state.core.outbox.len(), 1);
        assert_eq!(load(&path).unwrap().unwrap().core.outbox.len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn traffic_startup_prunes_expired_history_before_an_offline_policy_request() {
        let dir = directory();
        let path = dir.join("state");
        let mut state = expired_local_state();
        // Construct an older saved state without calling a mutating core method
        // that would already perform the expiry we are testing at CLI startup.
        let mut value = serde_json::to_value(&state.core).unwrap();
        value["traffic"]["enabled"] = serde_json::json!(true);
        state.core = serde_json::from_value(value).unwrap();
        state.server = "http://127.0.0.1:1".into();
        save(&path, &state).unwrap();
        assert!(!state.core.messages.is_empty());
        assert!(traffic_loop(&client().unwrap(), &path, &state.server, Some(1)).is_err());
        let stored = load(&path).unwrap().unwrap();
        assert!(stored.core.messages.is_empty());
        assert!(stored.core.outbox.is_empty());
        assert_eq!(
            serde_json::to_value(stored.core.key_upload()).unwrap(),
            serde_json::to_value(state.core.key_upload()).unwrap()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn desktop_config_extracts_credentials_not_untrusted_endpoints() {
        let dir = directory();
        let path = dir.join("oauth.json");
        std::fs::write(&path, br#"{"installed":{"client_id":"desktop.apps.googleusercontent.com","client_secret":"secret","auth_uri":"https://attacker.invalid"}}"#).unwrap();
        let (id, secret) = desktop_config(&path).unwrap();
        assert_eq!(id, "desktop.apps.googleusercontent.com");
        assert_eq!(secret.as_deref(), Some("secret"));
        std::fs::write(
            &path,
            br#"{"web":{"client_id":"web.apps.googleusercontent.com"}}"#,
        )
        .unwrap();
        assert!(desktop_config(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    fn maintenance_http_request(stream: &mut std::net::TcpStream) -> (String, Value) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut byte = [0];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 16384);
        }
        let headers = String::from_utf8(bytes).unwrap();
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(length < 65536);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        (
            headers.lines().next().unwrap().to_string(),
            if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            },
        )
    }
    fn maintenance_http_response(stream: &mut std::net::TcpStream, value: &Value) {
        let body = serde_json::to_vec(value).unwrap();
        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
        stream.write_all(&body).unwrap();
    }
    #[test]
    fn maintenance_saves_private_keys_before_http_and_retries_exact_journal_after_lost_reply() {
        let dir = directory();
        let path = dir.join("state");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        core.confirm_initial_upload().unwrap();
        let mut inventory = KeyMaintenanceState {
            generation: 0,
            keys: core.key_upload(),
        };
        inventory.keys.pre_keys.clear();
        let mut state = LocalState {
            server: format!("http://{}", listener.local_addr().unwrap()),
            token: "synthetic".into(),
            expires_at: test_deadline(),
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        let saved_path = path.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                maintenance_http_request(&mut stream).0,
                "GET /v1/keys/maintenance HTTP/1.1"
            );
            maintenance_http_response(&mut stream, &serde_json::to_value(inventory).unwrap());
            drop(stream);
            let (mut stream, _) = listener.accept().unwrap();
            let (method, first) = maintenance_http_request(&mut stream);
            assert_eq!(method, "PUT /v1/keys/maintenance HTTP/1.1");
            let disk = load(&saved_path).unwrap().unwrap();
            assert_eq!(
                serde_json::to_value(disk.core.pending_key_maintenance().unwrap()).unwrap(),
                first
            );
            assert_eq!(
                serde_json::to_value(&disk.core).unwrap()["prekeys"]
                    .as_object()
                    .unwrap()
                    .len(),
                64
            );
            drop(stream); // Uncertain response: relay may already have committed.
            let (mut stream, _) = listener.accept().unwrap();
            let (method, retry) = maintenance_http_request(&mut stream);
            assert_eq!(method, "PUT /v1/keys/maintenance HTTP/1.1");
            assert_eq!(retry, first);
            assert_eq!(
                serde_json::to_value(
                    load(&saved_path)
                        .unwrap()
                        .unwrap()
                        .core
                        .pending_key_maintenance()
                        .unwrap()
                )
                .unwrap(),
                first
            );
            maintenance_http_response(
                &mut stream,
                &serde_json::json!({"operation_id":first["operation_id"],"generation":1}),
            );
        });
        let transport = client().unwrap();
        assert!(maintain_keys(&transport, &path, &mut state, false).is_err());
        assert!(state.core.pending_key_maintenance().is_some());
        state = load(&path).unwrap().unwrap();
        maintain_keys(&transport, &path, &mut state, false).unwrap();
        assert!(state.core.pending_key_maintenance().is_none());
        assert!(
            load(&path)
                .unwrap()
                .unwrap()
                .core
                .pending_key_maintenance()
                .is_none()
        );
        assert_eq!(state.core.key_upload().pre_keys.len(), 32);
        server.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn interrupted_initial_upload_reuses_saved_identity_and_confirms_before_maintenance() {
        let dir = directory();
        let path = dir.join("state");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
        let public = serde_json::to_value(core.key_upload()).unwrap();
        let inventory = KeyMaintenanceState {
            generation: 0,
            keys: core.key_upload(),
        };
        let mut state = LocalState {
            server: format!("http://{}", listener.local_addr().unwrap()),
            token: "synthetic".into(),
            expires_at: test_deadline(),
            core,
            contact_identity_changes: Default::default(),
        };
        save(&path, &state).unwrap();
        let saved_path = path.clone();
        let server = std::thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let (method, body) = maintenance_http_request(&mut stream);
                assert_eq!(method, "PUT /v1/keys HTTP/1.1");
                assert_eq!(body, public);
                assert!(
                    load(&saved_path)
                        .unwrap()
                        .unwrap()
                        .core
                        .initial_upload_pending()
                );
                if attempt == 1 {
                    maintenance_http_response(&mut stream, &Value::Null);
                }
            }
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(
                maintenance_http_request(&mut stream).0,
                "GET /v1/keys/maintenance HTTP/1.1"
            );
            assert!(
                !load(&saved_path)
                    .unwrap()
                    .unwrap()
                    .core
                    .initial_upload_pending()
            );
            maintenance_http_response(&mut stream, &serde_json::to_value(inventory).unwrap());
        });
        let transport = client().unwrap();
        assert!(maintain_keys(&transport, &path, &mut state, true).is_err());
        assert!(state.core.initial_upload_pending());
        state = load(&path).unwrap().unwrap();
        maintain_keys(&transport, &path, &mut state, true).unwrap();
        assert!(!state.core.initial_upload_pending());
        server.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn fresh_login_after_deleted_initial_upload_never_publishes_or_adopts_new_bearer() {
        for changed in [false, true] {
            let dir = directory();
            let path = dir.join("state");
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let core = futures::executor::block_on(State::initialize("test@gmail.com")).unwrap();
            let mut foreign = core.key_upload();
            foreign.signed_pre_key.signature = "changed key".into();
            let mut state = LocalState {
                server: format!("http://{}", listener.local_addr().unwrap()),
                token: "original-session".into(),
                expires_at: test_deadline(),
                core,
                contact_identity_changes: Default::default(),
            };
            save(&path, &state).unwrap();
            let original = serde_json::to_value(&state).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                assert_eq!(
                    maintenance_http_request(&mut stream).0,
                    "GET /v1/keys/me HTTP/1.1"
                );
                if changed {
                    maintenance_http_response(&mut stream, &serde_json::to_value(foreign).unwrap());
                } else {
                    stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"error\":\"not found\"}").unwrap();
                }
                drop(stream);
                listener
            });
            let login = LoginResponse {
                token: "new-generation-session".into(),
                email: "test@gmail.com".into(),
                expires_at: test_deadline(),
            };
            assert!(bind_existing_login(&client().unwrap(), &mut state, login).is_err());
            assert_eq!(serde_json::to_value(&state).unwrap(), original);
            assert_eq!(
                serde_json::to_value(load(&path).unwrap().unwrap()).unwrap(),
                original
            );
            let listener = server.join().unwrap();
            listener.set_nonblocking(true).unwrap();
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
}
