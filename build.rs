fn main() {
    println!("cargo:rerun-if-changed=web/dist");
    assert!(
        std::path::Path::new("web/dist/index.html").exists(),
        "Build the inspector first: npm --prefix web ci && npm --prefix web run build"
    );
}
