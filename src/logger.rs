use ansi_term::{ANSIString, Style};
use ansi_term::Colour::{Blue, Red, Yellow};
use clap::ArgMatches;
use fern;
use log::{self, LogLevel};
use time;


fn color_from_log_level<'a>(level: &log::LogLevel, msg: &'a str) -> ANSIString<'a> {
  match *level {
    LogLevel::Error  => Red.paint(msg),
    LogLevel::Warn   => Yellow.paint(msg),
    LogLevel::Info   => Style::default().paint(msg),
    LogLevel::Debug  => Blue.paint(msg),
    LogLevel::Trace  => Style::default().paint(msg),
  }
}


pub fn init_logger_config(matches: &ArgMatches) {
  let level = match matches.occurrences_of("debug") {
    0 =>     log::LogLevelFilter::Warn,
    1 =>     log::LogLevelFilter::Info,
    2 =>     log::LogLevelFilter::Debug,
    3 | _ => log::LogLevelFilter::Trace,
  };

  let logger_config = fern::DispatchConfig {
    format: Box::new(|msg: &str, level: &log::LogLevel, _location: &log::LogLocation| {
      // Format the time.
      let time = time::now();
      let time_str = time.strftime("%Y-%m-%d][%H:%M:%S").unwrap();

      // Format the message header.
      let header = format!("{:<5} | [{}] | ", level, time_str);

      // Colorize message header.
      let cheader = color_from_log_level(level, &header);

      // Print final log message.
      format!("{}{}", cheader, msg)
    }),

    output: vec![fern::OutputConfig::stderr()],

    level: level,
  };

  if let Err(e) = fern::init_global_logger(logger_config, log::LogLevelFilter::Trace) {
    panic!("Failed to initialize global logger: {}", e);
  }
}
