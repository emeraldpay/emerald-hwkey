use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=EMRLD_HWKEY_TEST");
    // println!("cargo:rerun-if-env-changed=EMRLD_HWKEY_UNIT_TEST");
    match env::var("EMRLD_HWKEY_TEST") {
        Ok(v) => {
            println!("cargo:rustc-cfg=integration_test");
            for c in v.split(",") {
                println!("cargo:rustc-cfg={}", c);
            }
        },
        Err(_) => {},
    }

}
