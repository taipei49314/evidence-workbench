fn main() {
    println!("cargo:rerun-if-env-changed=EWB_TEST_NATIVE_SHA256");
    let digest = std::env::var("EWB_TEST_NATIVE_SHA256").unwrap_or_else(|_| {
        // Unit semantic fixtures snapshot these exact bytes. CLI integration
        // builds override this with the compiled fake executable's digest.
        "9fe66fa32138b1127125fa555a99d63d5b2f84c3d049c5c3618ab9fcaa43161a".to_owned()
    });
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "EWB_TEST_NATIVE_SHA256 must be lowercase SHA-256"
    );
    println!("cargo:rustc-env=EWB_TEST_NATIVE_SHA256={digest}");
}
