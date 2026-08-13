use std::fs;
use std::io::{self, Write};

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("--version") => {
            // A plan must never reach this branch. Tests look for the marker.
            fs::write(".fake-version-probe-ran", b"yes").expect("write probe marker");
            println!("greenwash fake 1.0.0");
        }
        Some("check") => {
            let mode = fs::read_to_string(".fake-mode").unwrap_or_default();
            match mode.trim() {
                "duplicate-json" => {
                    println!("{{\"verdict\":\"pass\",\"verdict\":\"block\"}}");
                }
                "pass-exit-one" => {
                    println!("{{\"verdict\":\"pass\"}}");
                    std::process::exit(1);
                }
                "hang" => {
                    std::thread::sleep(std::time::Duration::from_secs(30));
                }
                "oversized-output" => {
                    let mut stdout = io::stdout().lock();
                    let chunk = [b'x'; 64 * 1024];
                    for _ in 0..=512 {
                        stdout.write_all(&chunk).expect("write oversized output");
                    }
                    stdout.flush().expect("flush oversized output");
                }
                _ => {
                    println!("{{\"verdict\":\"block\",\"fixture\":true}}");
                    std::process::exit(1);
                }
            }
        }
        Some("--output") => {
            let mode = fs::read_to_string(".fake-mode").unwrap_or_default();
            match mode.trim() {
                "duplicate-json" => println!("{{\"status\":\"pass\",\"status\":\"block\"}}"),
                "hang" => std::thread::sleep(std::time::Duration::from_secs(30)),
                "mutate-subject" => {
                    fs::write("evidence.txt", b"mutated by native\n").expect("mutate subject");
                    println!("{{\"status\":\"inspected\"}}");
                }
                "oversized-output" => {
                    let mut stdout = io::stdout().lock();
                    let chunk = [b'x'; 64 * 1024];
                    for _ in 0..=512 {
                        stdout.write_all(&chunk).expect("write oversized output");
                    }
                    stdout.flush().expect("flush oversized output");
                }
                _ => {
                    println!("{{\"status\":\"inspected\",\"fixture\":true}}");
                    std::process::exit(1);
                }
            }
        }
        Some("emit-duplicate-json") => {
            println!("{{\"verdict\":\"pass\",\"verdict\":\"block\"}}");
        }
        Some("emit-pass-exit-one") => {
            println!("{{\"verdict\":\"pass\"}}");
            std::process::exit(1);
        }
        _ => {
            eprintln!("unsupported fake invocation: {arguments:?}");
            std::process::exit(2);
        }
    }
}
