use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};
use blazesym::symbolize;
use nix::sys::sysinfo;

pub const MAX_STACK_DEPTH: usize = 128;
pub const TASK_COMM_LEN: usize = 16;
const ADDR_WIDTH: usize = 16;

#[repr(C)]
pub struct StacktraceEvent {
    pub pid: u32,
    pub cpu_id: u32,
    pub timestamp: u64,
    pub comm: [u8; TASK_COMM_LEN],
    pub kstack_size: i32,
    pub ustack_size: i32,
    pub kstack: [u64; MAX_STACK_DEPTH],
    pub ustack: [u64; MAX_STACK_DEPTH],
}

pub enum OutputFormat {
    Standard,
    FoldedExtended,
}

pub struct EventHandler {
    symbolizer: symbolize::Symbolizer,
    format: OutputFormat,
    boot_time_ns: u64,
}

impl EventHandler {
    pub fn new(format: OutputFormat) -> Self {
        let boot_time_ns = Self::get_boot_time_ns();
        Self {
            symbolizer: symbolize::Symbolizer::new(),
            format,
            boot_time_ns,
        }
    }

    fn get_boot_time_ns() -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before Unix epoch");
        let now_ns = now.as_nanos() as u64;

        let info = sysinfo::sysinfo().expect("Failed to get sysinfo");
        let uptime_ns = (info.uptime().as_secs_f64() * 1_000_000_000.0) as u64;

        now_ns - uptime_ns
    }

    pub fn handle(&self, data: &[u8]) -> ::std::os::raw::c_int {
        if data.len() != mem::size_of::<StacktraceEvent>() {
            eprintln!(
                "Invalid size {} != {}",
                data.len(),
                mem::size_of::<StacktraceEvent>()
            );
            return 1;
        }

        let event = unsafe { &*(data.as_ptr() as *const StacktraceEvent) };

        if event.kstack_size <= 0 && event.ustack_size <= 0 {
            return 1;
        }

        match self.format {
            OutputFormat::Standard => self.handle_standard(event),
            OutputFormat::FoldedExtended => self.handle_folded_extended(event),
        }

        0
    }

    fn get_stack_slice<'a>(stack: &'a [u64; MAX_STACK_DEPTH], size: i32) -> &'a [u64] {
        if size > 0 {
            &stack[0..(size as usize / mem::size_of::<u64>())]
        } else {
            &[]
        }
    }

    fn get_comm_str(comm: &[u8; TASK_COMM_LEN]) -> &str {
        std::str::from_utf8(comm)
            .unwrap_or("<unknown>")
            .trim_end_matches('\0')
    }

    fn handle_standard(&self, event: &StacktraceEvent) {
        let comm = Self::get_comm_str(&event.comm);
        let unix_timestamp_ns = event.timestamp + self.boot_time_ns;
        let timestamp_sec = unix_timestamp_ns / 1_000_000_000;
        let timestamp_nsec = unix_timestamp_ns % 1_000_000_000;
        println!("[{}.{:09}] COMM: {} (pid={}) @ CPU {}",
            timestamp_sec, timestamp_nsec, comm, event.pid, event.cpu_id);

        if event.kstack_size > 0 {
            println!("Kernel:");
            let kstack = Self::get_stack_slice(&event.kstack, event.kstack_size);
            show_stack_trace(kstack, &self.symbolizer, 0);
        } else {
            println!("No Kernel Stack");
        }

        if event.ustack_size > 0 {
            println!("Userspace:");
            let ustack = Self::get_stack_slice(&event.ustack, event.ustack_size);
            show_stack_trace(ustack, &self.symbolizer, event.pid);
        } else {
            println!("No Userspace Stack");
        }

        println!();
    }

    fn handle_folded_extended(&self, event: &StacktraceEvent) {
        let comm = Self::get_comm_str(&event.comm);
        let tid = event.pid;

        let mut stack_frames = Vec::new();

        if event.ustack_size > 0 {
            let ustack = Self::get_stack_slice(&event.ustack, event.ustack_size);
            let user_frames = symbolize_stack_to_vec(&self.symbolizer, ustack, event.pid);

            for frame in user_frames.iter().rev() {
                stack_frames.push(frame.clone());
            }
        }

        if event.kstack_size > 0 {
            let kstack = Self::get_stack_slice(&event.kstack, event.kstack_size);
            let kernel_frames = symbolize_stack_to_vec(&self.symbolizer, kstack, 0);

            for frame in kernel_frames.iter().rev() {
                stack_frames.push(format!("{}_[k]", frame));
            }
        }

        let unix_timestamp_ns = event.timestamp + self.boot_time_ns;
        println!(
            "{} {} {} {} {} {}",
            unix_timestamp_ns,
            comm,
            event.pid,
            tid,
            event.cpu_id,
            stack_frames.join(";")
        );
    }
}

fn print_frame(
    name: &str,
    addr_info: Option<(blazesym::Addr, blazesym::Addr, usize)>,
    code_info: Option<&symbolize::CodeInfo>,
) {
    let code_info = code_info.as_ref().map(|code_info| {
        let path = code_info.to_path();
        let path = path.display();

        match (code_info.line, code_info.column) {
            (Some(line), Some(col)) => format!(" {path}:{line}:{col}"),
            (Some(line), None) => format!(" {path}:{line}"),
            (None, _) => format!(" {path}"),
        }
    });
    if let Some((input_addr, addr, offset)) = addr_info {
        println!(
            "{input_addr:#0width$x}: {name} @ {addr:#x}+{offset:#x}{code_info}",
            code_info = code_info.as_deref().unwrap_or(""),
            width = ADDR_WIDTH
        )
    } else {
        println!(
            "{:width$}  {name}{code_info} [inlined]",
            " ",
            code_info = code_info
                .map(|info| format!(" @{info}"))
                .as_deref()
                .unwrap_or(""),
            width = ADDR_WIDTH
        )
    }
}

fn convert_stack_addresses(stack: &[u64]) -> Vec<blazesym::Addr> {
    if mem::size_of::<blazesym::Addr>() != mem::size_of::<u64>() {
        stack
            .iter()
            .copied()
            .map(|addr| addr as blazesym::Addr)
            .collect::<Vec<_>>()
    } else {
        stack.iter().copied().map(|addr| addr as blazesym::Addr).collect()
    }
}

fn get_stack_slice<'a>(stack: &'a [u64], converted: &'a [blazesym::Addr]) -> &'a [blazesym::Addr] {
    if mem::size_of::<blazesym::Addr>() != mem::size_of::<u64>() {
        converted
    } else {
        unsafe { mem::transmute::<_, &[blazesym::Addr]>(stack) }
    }
}

fn get_symbolize_source(pid: u32) -> symbolize::source::Source<'static> {
    if pid == 0 {
        symbolize::source::Source::from(symbolize::source::Kernel::default())
    } else {
        symbolize::source::Source::from(symbolize::source::Process::new(pid.into()))
    }
}

fn symbolize_stack_to_vec(symbolizer: &symbolize::Symbolizer, stack: &[u64], pid: u32) -> Vec<String> {
    let converted = convert_stack_addresses(stack);
    let stack_addrs = get_stack_slice(stack, &converted);
    let src = get_symbolize_source(pid);

    let syms = match symbolizer.symbolize(&src, symbolize::Input::AbsAddr(stack_addrs)) {
        Ok(syms) => syms,
        Err(_) => {
            return stack_addrs.iter().map(|addr| format!("{:#x}", addr)).collect();
        }
    };

    let mut result = Vec::new();
    for (addr, sym) in stack_addrs.iter().copied().zip(syms) {
        match sym {
            symbolize::Symbolized::Sym(symbolize::Sym {
                name,
                ..
            }) => {
                result.push(name.to_string());
            }
            symbolize::Symbolized::Unknown(..) => {
                result.push(format!("{:#x}", addr));
            }
        }
    }
    result
}

fn show_stack_trace(stack: &[u64], symbolizer: &symbolize::Symbolizer, pid: u32) {
    let converted = convert_stack_addresses(stack);
    let stack_addrs = get_stack_slice(stack, &converted);
    let src = get_symbolize_source(pid);

    let syms = match symbolizer.symbolize(&src, symbolize::Input::AbsAddr(stack_addrs)) {
        Ok(syms) => syms,
        Err(err) => {
            eprintln!(" failed to symbolize addresses: {err:#}");
            return;
        }
    };

    for (input_addr, sym) in stack_addrs.iter().copied().zip(syms) {
        match sym {
            symbolize::Symbolized::Sym(symbolize::Sym {
                name,
                addr,
                offset,
                code_info,
                inlined,
                ..
            }) => {
                let ci_ref = code_info.as_deref();
                print_frame(&name, Some((input_addr, addr, offset)), ci_ref);
                for frame in inlined.iter() {
                    let frame_ci_ref = frame.code_info.as_ref();
                    print_frame(&frame.name, None, frame_ci_ref);
                }
            }
            symbolize::Symbolized::Unknown(..) => {
                println!("{input_addr:#0width$x}: <no-symbol>", width = ADDR_WIDTH)
            }
        }
    }
}
