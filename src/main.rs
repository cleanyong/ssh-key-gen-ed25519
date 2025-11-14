use clap::Parser;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Parser, Debug)]
#[command(
    name = "ssh-key-gen-ed25519",
    about = "Minimal ssh-keygen -t ed25519 replacement" ,
    disable_help_subcommand = true
)]
struct Args {
    /// Base filename for the key pair (defaults to id_ed25519)
    #[arg(long = "output", short = 'f', value_name = "PATH", default_value = "id_ed25519")]
    output: PathBuf,

    /// Optional comment appended to the public key line
    #[arg(long = "comment", short = 'C')]
    comment: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let private_path = args.output;
    let public_path = public_path(&private_path);

    if private_path.exists() || public_path.exists() {
        return Err(format!(
            "Refusing to overwrite existing key files: {:?} / {:?}",
            private_path, public_path
        ));
    }

    let mut rng = rand_core::OsRng;
    let private_key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .map_err(|err| format!("failed generating key: {err}"))?;

    save_private_key(&private_key, &private_path)?;
    save_public_key(&private_key, &public_path, args.comment.as_deref())?;

    println!(
        "Generated new Ed25519 key pair:\n  Private: {:?}\n  Public:  {:?}",
        private_path, public_path
    );

    Ok(())
}

fn save_private_key(key: &PrivateKey, path: &Path) -> Result<(), String> {
    let data = key
        .to_openssh(LineEnding::LF)
        .map_err(|err| format!("failed to encode private key: {err}"))?;
    fs::write(path, data.as_bytes())
        .map_err(|err| format!("failed to write private key {:?}: {err}", path))?;
    // Restrict permissions on Unix if possible
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            eprintln!("Warning: unable to set 0600 permissions on {:?}: {}", path, err);
        }
    }
    Ok(())
}

fn save_public_key(
    private_key: &PrivateKey,
    path: &Path,
    comment: Option<&str>,
) -> Result<(), String> {
    let mut line = private_key
        .public_key()
        .to_openssh()
        .map_err(|err| format!("failed to encode public key: {err}"))?;
    if let Some(comment) = comment {
        line.push(' ');
        line.push_str(comment);
    }
    line.push('\n');
    fs::write(path, line)
        .map_err(|err| format!("failed to write public key {:?}: {err}", path))?;
    Ok(())
}

fn public_path(private_path: &Path) -> PathBuf {
    let mut pub_path = private_path.as_os_str().to_os_string();
    pub_path.push(".pub");
    PathBuf::from(pub_path)
}
