extern crate aho_corasick;
extern crate ansi_term;
extern crate byteorder;
extern crate clap;
extern crate fern;
extern crate handlebars;
#[macro_use] extern crate itertools;
extern crate libc;
#[macro_use] extern crate log;
extern crate mmap;
extern crate rustc_serialize;
extern crate time;

use std::collections::BTreeMap;
use std::fs;

use aho_corasick::{Automaton, AcAutomaton};
use clap::{Arg, App, SubCommand};
use handlebars::Handlebars;
use itertools::Itertools;
use mmap::{MemoryMap, MapOption};
use rustc_serialize::json::{Json, ToJson};

mod endian;
mod logger;
mod patterns;


fn main() {
    let matches = App::new("myapp")
        .version("0.0.1")
        .author("Andrew Dunham <andrew@du.nham.ca>")
        .about("Searches files for patterns that indicate cryptographic algorithms")
        .arg(Arg::with_name("debug")
             .short("d")
             .multiple(true)
             .help("Sets the level of debugging information"))
        .subcommand_required(true)
        .subcommand(SubCommand::with_name("scan")
                    .about("Search the given input file(s)")
                    .arg(Arg::with_name("template")
                         .long("template")
                         .takes_value(true)
                         .help("Handlebars template specifying the output format for found items."))
                    .arg(Arg::with_name("input")
                         .help("Sets the input file(s) to search")
                         .required(true)
                         .multiple(true)
                         ))
        .subcommand(SubCommand::with_name("list")
                    .about("Lists available signatures"))
        .get_matches();
    logger::init_logger_config(&matches);

    let patterns = patterns::get_patterns();

    if let Some(_) = matches.subcommand_matches("list") {
        println!("Supported signatures:\n--------------------------------------------------");
        for pat in patterns.into_iter().unique_by(|p| p.algorithm) {
            println!(" - {}", pat.algorithm);
        }
    } else if let Some(submatches) = matches.subcommand_matches("scan") {
        debug!("Compiling Handlebars template");
        let mut hbs = Handlebars::new();
        let template = submatches.value_of("template")
            .unwrap_or("{{path}}:{{address}}:{{algorithm}} ({{endian}}) - {{desc}}");

        if let Err(e) = hbs.register_template_string("crypt", template.to_string()) {
            error!("Could not compile template string: {}", e);
            return;
        }

        // Build Aho-Corasick automaton.
        debug!("Creating Aho-Corasick automaton");
        let at = build_automaton(&patterns);

        debug!("Starting search");
        if let Some(ref input_paths) = submatches.values_of("input") {
            for input_path in input_paths {
                info!("Searching file: {}", input_path);
                search_file(&patterns, &at, input_path, &hbs);
            }
        } else {
            warn!("No input file(s) given");
        }
    }
}

fn build_automaton(patterns: &Vec<patterns::Pattern>) -> AcAutomaton<Vec<u8>> {
    let mut patterns_vec = vec![];

    for pat in patterns {
        // NOTE: Order matters here! See comment in `search_file`.
        patterns_vec.push(pat.bytes.as_byte_vec(endian::Endianness::LittleEndian));
        patterns_vec.push(pat.bytes.as_byte_vec(endian::Endianness::BigEndian));
    }

    AcAutomaton::new(patterns_vec)
}


fn search_file<P>(patterns: &Vec<patterns::Pattern>, at: &AcAutomaton<Vec<u8>>, input_path: P, hbs: &Handlebars)
where P: std::convert::AsRef<std::path::Path>
{
    let path = input_path.as_ref();

    with_file_mmap(path, |map| {
        // Run the automaton on the file!
        for mm in at.stream_find(map) {
            // Reading should never fail, since we're using a mmap'd buffer.
            let mtch = mm.unwrap();

            // When building, we added two patterns to the automaton - little
            // endian and big-endian, in that order.  Reverse this back to the
            // corresponding `Pattern`.
            let pati = mtch.pati / 2;
            let endian = if mtch.pati % 2 == 0 {
                "LE"
            } else {
                "BE"
            };
            let pattern = &patterns[pati];

            // Insert information into a map that we use for rendering.
            let mut info = BTreeMap::<String, Json>::new();

            info.insert("path".to_string(),      format!("{}", path.display()).to_json());
            info.insert("address".to_string(),   format!("0x{:08x}", mtch.start).to_json());
            info.insert("algorithm".to_string(), pattern.algorithm.to_json());
            info.insert("endian".to_string(),    endian.to_json());
            info.insert("desc".to_string(),      pattern.desc.to_json());

            // Run the template.
            let res = match hbs.render("crypt", &info) {
                Ok(r)  => r,
                Err(_) => "error rendering template".to_string(),
            };

            println!("{}", res);
        }
    });
}


// --------------------------------------------------

#[cfg(unix)]
fn get_fd(file: &fs::File) -> libc::c_int {
    use std::os::unix::io::AsRawFd;
    file.as_raw_fd()
}

#[cfg(windows)]
fn get_fd(file: &fs::File) -> libc::HANDLE {
    use std::os::windows::io::AsRawHandle;
    file.as_raw_handle() as libc::HANDLE
}

fn with_file_mmap<P, F, T>(path: P, f: F) -> T
where P: std::convert::AsRef<std::path::Path>,
      F: Fn(&[u8]) -> T
{
    let file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap();

    // Get the size of the file.
    let len = file.metadata().unwrap().len() as usize;

    let fd = get_fd(&file);

    let chunk = MemoryMap::new(len, &[
                               MapOption::MapReadable,
                               MapOption::MapFd(fd),
    ]).unwrap();

    let file_data: &[u8] = unsafe {
        std::slice::from_raw_parts(chunk.data() as *const _, chunk.len())
    };

    f(file_data)
}
