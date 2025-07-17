use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=EMRLD_HWKEY_TEST");
    if let Ok(v) = env::var("EMRLD_HWKEY_TEST") {
        println!("cargo:rustc-cfg=integration_test");
        for c in v.split(",") {
            let test_name = if c.starts_with("test_") {
                c.to_string()
            } else {
                format!("test_{}", c)
            };
            println!("cargo:rustc-cfg={}", test_name);
        }
    }

}
