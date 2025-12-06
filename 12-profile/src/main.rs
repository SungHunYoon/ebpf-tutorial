use std::mem::MaybeUninit;
use std::time::Duration;
use clap::{ArgAction, Parser};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};

mod profile {
    include!(concat!(env!("OUT_DIR"), "/profile.skel.rs"));
}
mod syscall;
mod event;
mod perf;

use profile::*;

#[derive(Parser, Debug)]
struct Args {
    /// Sampling frequency
    #[arg(short, default_value_t = 50)]
    freq: u64,

    /// Increase verbosity (can be supplied multiple times)
    #[arg(short = 'v', long = "verbose", global = true, action = ArgAction::Count)]
    verbosity: u8,

    /// Use software event for triggering stack trace capture
    #[arg(long = "sw-event")]
    sw_event: bool,

    /// Filter by PID (optional)
    #[arg(short = 'p', long = "pid")]
    pid: Option<i32>,

    /// Output in extended folded format
    #[arg(short = 'E', long = "fold-extend")]
    fold_extend: bool,
}

fn main() -> Result<(), libbpf_rs::Error> {
    let args = Args::parse();

    let skel_builder = ProfileSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let skel = open_skel.load()?;

    let pefds = perf::init_perf_monitor(args.freq, args.sw_event, args.pid)?;
    let _links = perf::attach_perf_event(&pefds, &skel.progs.profile);

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    let output_format = if args.fold_extend {
        event::OutputFormat::FoldedExtended
    } else {
        event::OutputFormat::Standard
    };

    let event_handler = event::EventHandler::new(output_format);
    builder.add(&skel.maps.events, move |data| {
        event_handler.handle(data)
    })?;

    let ringbuf = builder.build()?;
    while ringbuf.poll(Duration::MAX).is_ok() {}

    perf::close_perf_events(pefds)?;
    Ok(())
}
