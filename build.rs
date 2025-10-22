use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

#[cfg(unix)]
use std::os::unix::fs as unix_fs;

const LLVM_PREFIX_ENV: &str = "LLVM_SYS_181_PREFIX";
const LLVM_CONFIG_ENV: &str = "LLVM_CONFIG_PATH";
const MIN_LLVM_MAJOR: u32 = 18;
const MIN_LLVM_MINOR: u32 = 1;

struct ForcedLibrary {
    name: &'static str,
    search_dirs: &'static [&'static str],
}

const FORCED_LIBRARIES: &[ForcedLibrary] = &[ForcedLibrary {
    name: "zstd",
    search_dirs: &[
        "/opt/homebrew/opt/zstd/lib",
        "/usr/local/opt/zstd/lib",
        "/opt/homebrew/lib",
        "/usr/local/lib",
    ],
}];

const SKIP_LIBRARIES: &[&str] = &["Polly", "PollyISL"];

const SKIP_SYSTEM_LIBS: &[&str] = &["z3"];

static RPATH_EMITTED: OnceLock<()> = OnceLock::new();

#[derive(Clone, Copy)]
enum LinkMode {
    Static,
    Dynamic,
}

impl LinkMode {
    fn flag(self) -> Option<&'static str> {
        match self {
            LinkMode::Static => Some("--link-static"),
            LinkMode::Dynamic => Some("--link-shared"),
        }
    }

    fn kind(self) -> &'static str {
        match self {
            LinkMode::Static => "static",
            LinkMode::Dynamic => "dylib",
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed={LLVM_PREFIX_ENV}");
    println!("cargo:rerun-if-env-changed={LLVM_CONFIG_ENV}");
    println!("cargo:rerun-if-env-changed=PATH");

    let llvm_config = locate_llvm_config().unwrap_or_else(|| {
        panic!(
            "Unable to locate llvm-config for LLVM >= {MIN_LLVM_MAJOR}.{MIN_LLVM_MINOR}. \
             Set {LLVM_PREFIX_ENV} or {LLVM_CONFIG_ENV} to override."
        )
    });

    println!("cargo:rerun-if-changed={}", llvm_config.display());

    let (link_mode, libraries) = match collect_library_paths(&llvm_config, LinkMode::Static) {
        Ok(libs) if !libs.is_empty() => (LinkMode::Static, libs),
        _ => {
            println!(
                "cargo:warning=Falling back to shared LLVM libraries; static archives were not found."
            );
            let libs = collect_library_paths(&llvm_config, LinkMode::Dynamic)
                .expect("Failed to query shared LLVM libraries via llvm-config");
            if libs.is_empty() {
                panic!("llvm-config did not return any libraries to link against");
            }
            (LinkMode::Dynamic, libs)
        }
    };

    emit_library_search_paths(&libraries);
    emit_library_links(&libraries, link_mode);
    emit_system_libraries(&llvm_config, link_mode);
    emit_ldflags(&llvm_config, link_mode);
    emit_additional_search_paths();
    emit_cxx_runtime();
}

fn locate_llvm_config() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(explicit) = env::var(LLVM_CONFIG_ENV) {
        candidates.push(PathBuf::from(explicit));
    }

    if let Ok(prefix) = env::var(LLVM_PREFIX_ENV) {
        let base = PathBuf::from(prefix).join("bin");
        candidates.extend(
            candidate_binary_names()
                .into_iter()
                .map(|bin| base.join(bin)),
        );
    }

    if let Some(path_env) = env::var_os("PATH") {
        for dir in env::split_paths(&path_env) {
            for bin in candidate_binary_names() {
                candidates.push(dir.join(&bin));
            }
        }
    }

    for root in ["/opt/homebrew/opt", "/usr/local/opt"] {
        for suffix in ["llvm@18", "llvm"] {
            let base = Path::new(root).join(suffix).join("bin");
            for bin in candidate_binary_names() {
                candidates.push(base.join(&bin));
            }
        }
    }

    let mut seen = HashSet::new();
    for path in candidates {
        if !seen.insert(path.clone()) {
            continue;
        }

        if !path.is_file() {
            continue;
        }

        if version_matches(&path) {
            return Some(path);
        }
    }

    None
}

fn candidate_binary_names() -> Vec<String> {
    let mut names = vec![
        "llvm-config".to_string(),
        format!("llvm-config-{}", MIN_LLVM_MAJOR),
        format!("llvm-config{}", MIN_LLVM_MAJOR),
        format!("llvm{}-config", MIN_LLVM_MAJOR),
        format!("llvm-config-{}.{}", MIN_LLVM_MAJOR, MIN_LLVM_MINOR),
        format!("llvm-config{}{}", MIN_LLVM_MAJOR, MIN_LLVM_MINOR),
    ];

    if cfg!(target_os = "windows") {
        names = names
            .into_iter()
            .flat_map(|name| [format!("{name}.exe"), format!("{name}.bat"), name])
            .collect();
    }

    names
}

fn version_matches(binary: &Path) -> bool {
    let output = match Command::new(binary).arg("--version").output() {
        Ok(output) => output,
        Err(_) => return false,
    };

    if !output.status.success() {
        return false;
    }

    let version = String::from_utf8_lossy(&output.stdout);
    parse_version_token(&version).map_or(false, |(major, minor)| {
        major > MIN_LLVM_MAJOR || (major == MIN_LLVM_MAJOR && minor >= MIN_LLVM_MINOR)
    })
}

fn parse_version_token(version: &str) -> Option<(u32, u32)> {
    let token = version.split_whitespace().next().unwrap_or_default();
    let mut parts = token.split('.');
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    major.map(|mj| (mj, minor))
}

fn collect_library_paths(llvm_config: &Path, mode: LinkMode) -> Result<Vec<PathBuf>, String> {
    let mut args = Vec::new();
    if let Some(flag) = mode.flag() {
        args.push(flag);
    }
    args.push("--libfiles");

    query_llvm_config(llvm_config, &args).map(|output| {
        output
            .split_whitespace()
            .map(PathBuf::from)
            .filter(|path| {
                path.is_file()
                    && library_name(path)
                        .map(|name| !is_skipped_library(&name))
                        .unwrap_or(true)
            })
            .collect()
    })
}

fn emit_library_search_paths(libraries: &[PathBuf]) {
    let mut seen = HashSet::new();
    for path in libraries {
        if let Some(dir) = path.parent() {
            if seen.insert(dir.to_path_buf()) {
                println!("cargo:rustc-link-search=native={}", dir.display());
            }
        }
    }
}

fn emit_library_links(libraries: &[PathBuf], mode: LinkMode) {
    let mut seen = HashSet::new();
    for path in libraries {
        if let Some(name) = library_name(path) {
            if is_skipped_library(&name) {
                continue;
            }
            if seen.insert(name.clone()) {
                println!("cargo:rustc-link-lib={}={}", mode.kind(), name);
            }
        }
    }
}

fn emit_system_libraries(llvm_config: &Path, mode: LinkMode) {
    let mut args = Vec::new();
    if let Some(flag) = mode.flag() {
        args.push(flag);
    }
    args.push("--system-libs");

    let output = match query_llvm_config(llvm_config, &args) {
        Ok(text) => text,
        Err(_) => return,
    };

    let mut libs = HashSet::new();
    let mut ordered_libs = Vec::new();
    let mut ordered_paths: Vec<PathBuf> = Vec::new();
    let mut frameworks = HashSet::new();
    let mut search = HashSet::new();
    let mut framework_search = HashSet::new();

    let mut tokens = output.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if let Some(name) = token.strip_prefix("-l") {
            if !name.is_empty() && libs.insert(name.to_string()) {
                let is_forced = is_forced_library(name);
                if is_forced {
                    ordered_libs.push(name.to_string());
                } else if !is_skipped_library(name) && !is_skipped_system_lib(name) {
                    ordered_libs.push(name.to_string());
                }
            }
        } else if let Some(path) = token.strip_prefix("-L") {
            if !path.is_empty() && search.insert(path.to_string()) {
                println!("cargo:rustc-link-search=native={path}");
            }
        } else if let Some(path) = token.strip_prefix("-F") {
            if !path.is_empty() && framework_search.insert(path.to_string()) {
                println!("cargo:rustc-link-search=framework={path}");
            }
        } else if token == "-framework" {
            if let Some(name) = tokens.next() {
                if frameworks.insert(name.to_string()) {
                    println!("cargo:rustc-link-lib=framework={name}");
                }
            }
        } else if looks_like_library_path(token) {
            ordered_paths.push(PathBuf::from(token));
        } else {
            println!("cargo:rustc-link-arg={token}");
        }
    }

    for name in ordered_libs {
        if handle_forced_library(&name, None) {
            continue;
        }
        if is_skipped_library(&name) || is_skipped_system_lib(&name) {
            continue;
        }
        println!("cargo:rustc-link-lib=dylib={name}");
    }

    for path in ordered_paths {
        if let Some(name) = forced_name_from_path(&path) {
            if handle_forced_library(name, Some(&path)) {
                continue;
            }
        } else if library_name(&path)
            .map(|name| is_skipped_library(&name) || is_skipped_system_lib(&name))
            .unwrap_or(false)
        {
            continue;
        }
        println!("cargo:rustc-link-arg={}", path.display());
    }
}

fn looks_like_library_path(token: &str) -> bool {
    token.ends_with(".a") || token.ends_with(".dylib") || token.ends_with(".so")
}

fn forced_name_from_path(path: &Path) -> Option<&'static str> {
    let file_name = path.file_name()?.to_str()?;
    FORCED_LIBRARIES
        .iter()
        .find(|lib| file_name.starts_with(&format!("lib{}", lib.name)))
        .map(|lib| lib.name)
}

fn is_forced_library(name: &str) -> bool {
    FORCED_LIBRARIES
        .iter()
        .any(|lib| lib.name == name || name.starts_with(&format!("{}.", lib.name)))
}

fn is_skipped_library(name: &str) -> bool {
    SKIP_LIBRARIES
        .iter()
        .any(|&skip| name == skip || name.starts_with(&format!("{skip}.")))
}

fn is_skipped_system_lib(name: &str) -> bool {
    SKIP_SYSTEM_LIBS
        .iter()
        .any(|&skip| name == skip || name.starts_with(&format!("{skip}.")))
}

fn emit_ldflags(llvm_config: &Path, mode: LinkMode) {
    let mut args = Vec::new();
    if let Some(flag) = mode.flag() {
        args.push(flag);
    }
    args.push("--ldflags");

    let output = match query_llvm_config(llvm_config, &args) {
        Ok(text) => text,
        Err(_) => return,
    };

    let mut search = HashSet::new();
    let mut framework_search = HashSet::new();

    for token in output.split_whitespace() {
        if let Some(path) = token.strip_prefix("-L") {
            if !path.is_empty() && search.insert(path.to_string()) {
                println!("cargo:rustc-link-search=native={path}");
            }
        } else if let Some(path) = token.strip_prefix("-F") {
            if !path.is_empty() && framework_search.insert(path.to_string()) {
                println!("cargo:rustc-link-search=framework={path}");
            }
        } else {
            println!("cargo:rustc-link-arg={token}");
        }
    }
}

fn emit_additional_search_paths() {
    const EXTRA_PATHS: &[&str] = &["/opt/homebrew/lib", "/usr/local/lib"];

    for path in EXTRA_PATHS {
        let dir = Path::new(path);
        if dir.exists() {
            println!("cargo:rustc-link-search=native={}", dir.display());
        }
    }
}

fn emit_cxx_runtime() {
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=dylib=c++");
        println!("cargo:rustc-link-lib=dylib=c++abi");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
}

fn handle_forced_library(name: &str, explicit_source: Option<&Path>) -> bool {
    let Some(forced) = find_forced_library(name) else {
        return false;
    };

    if let Some(archive) = locate_static_archive(forced, name) {
        println!("cargo:rustc-link-arg={}", archive.display());
        return true;
    }

    if let Some(bundle) = bundle_dynamic_library(forced, name, explicit_source) {
        println!("cargo:rustc-link-arg={}", bundle.library_path.display());
        println!(
            "cargo:rustc-link-arg=-Wl,-change,{},@rpath/lib{name}.dylib",
            bundle.original_path.display()
        );
        println!("cargo:rustc-link-search=native={}", bundle.dir.display());
        ensure_bundle_rpath();
        return true;
    }

    println!(
        "cargo:warning=Unable to locate static or bundleable copy of {name}; using system library"
    );
    false
}

fn find_forced_library(name: &str) -> Option<&'static ForcedLibrary> {
    FORCED_LIBRARIES.iter().find(|lib| lib.name == name)
}

fn locate_static_archive(lib: &ForcedLibrary, name: &str) -> Option<PathBuf> {
    for dir in lib.search_dirs {
        let candidate = Path::new(dir).join(format!("lib{name}.a"));
        if candidate.exists() {
            println!("cargo:rerun-if-changed={}", candidate.display());
            return Some(candidate);
        }
    }
    None
}

struct BundleInfo {
    dir: PathBuf,
    library_path: PathBuf,
    original_path: PathBuf,
}

fn bundle_dynamic_library(
    lib: &ForcedLibrary,
    name: &str,
    explicit_source: Option<&Path>,
) -> Option<BundleInfo> {
    if !cfg!(target_os = "macos") {
        return None;
    }

    let source = explicit_source.map(PathBuf::from).or_else(|| {
        lib.search_dirs
            .iter()
            .find_map(|dir| find_dynamic_candidate(Path::new(dir), name))
    })?;

    println!("cargo:rerun-if-changed={}", source.display());

    let destination_dir = bundle_output_dir()?;
    if let Err(err) = fs::create_dir_all(&destination_dir) {
        println!(
            "cargo:warning=Failed to create bundle directory {}: {}",
            destination_dir.display(),
            err
        );
        return None;
    }

    let base_name = format!("lib{name}.dylib");
    let destination = destination_dir.join(&base_name);
    if let Err(err) = fs::copy(&source, &destination) {
        println!(
            "cargo:warning=Failed to copy {} to {}: {}",
            source.display(),
            destination.display(),
            err
        );
        return None;
    }

    println!("cargo:warning=Bundling {name} from {}", source.display());

    if let Some(original_name) = source.file_name() {
        let original_name = original_name.to_string_lossy();
        if original_name != base_name {
            let versioned_path = destination_dir.join(&*original_name);
            #[cfg(unix)]
            {
                if versioned_path.exists() {
                    let _ = fs::remove_file(&versioned_path);
                }
                if let Err(err) = unix_fs::symlink(&destination, &versioned_path) {
                    println!(
                        "cargo:warning=Failed to create symlink {} -> {}: {}",
                        versioned_path.display(),
                        destination.display(),
                        err
                    );
                }
            }
            #[cfg(not(unix))]
            {
                if let Err(err) = fs::copy(&destination, &versioned_path) {
                    println!(
                        "cargo:warning=Failed to duplicate {} to {}: {}",
                        destination.display(),
                        versioned_path.display(),
                        err
                    );
                }
            }
        }
    }

    if let Err(err) = rewrite_install_name(&destination, name) {
        println!(
            "cargo:warning=Failed to rewrite install name for {}: {}",
            destination.display(),
            err
        );
        return None;
    }

    Some(BundleInfo {
        dir: destination_dir,
        library_path: destination,
        original_path: source,
    })
}

fn find_dynamic_candidate(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(format!("lib{name}.dylib"));
    if candidate.exists() {
        return Some(candidate);
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return None;
    };

    let prefix = format!("lib{name}");
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "dylib") {
            continue;
        }
        if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
            if file_name.starts_with(&prefix) {
                return Some(path);
            }
        }
    }

    None
}

fn bundle_output_dir() -> Option<PathBuf> {
    let profile = env::var("PROFILE").ok()?;
    let target_dir = env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            Path::new(&env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR")).join("target")
        });
    let primary = target_dir.join(&profile);
    let path = if primary.exists() {
        primary
    } else if let Ok(target_triple) = env::var("TARGET") {
        target_dir.join(target_triple).join(&profile)
    } else {
        primary
    };
    Some(path.join("lib"))
}

fn rewrite_install_name(path: &Path, name: &str) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Ok(());
    }

    let id = format!("@rpath/lib{name}.dylib");
    Command::new("install_name_tool")
        .arg("-id")
        .arg(&id)
        .arg(path)
        .status()
        .map_err(|err| format!("install_name_tool failed: {err}"))
        .and_then(|status| {
            if status.success() {
                Ok(())
            } else {
                Err(format!("install_name_tool exited with {}", status))
            }
        })
}

fn ensure_bundle_rpath() {
    RPATH_EMITTED.get_or_init(|| {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../lib");
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path/../lib");
    });
}

fn query_llvm_config(llvm_config: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(llvm_config)
        .args(args)
        .output()
        .map_err(|err| format!("Failed to run {}: {err}", llvm_config.display()))?;

    if !output.status.success() {
        return Err(format!(
            "{} {:?} exited with {}",
            llvm_config.display(),
            args,
            output.status
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn library_name(path: &Path) -> Option<String> {
    let file = path.file_name()?.to_str()?;
    let name = file
        .strip_suffix(".a")
        .or_else(|| file.strip_suffix(".lib"))
        .or_else(|| file.strip_suffix(".dylib"))
        .unwrap_or(file);
    Some(name.strip_prefix("lib").unwrap_or(name).to_string())
}
