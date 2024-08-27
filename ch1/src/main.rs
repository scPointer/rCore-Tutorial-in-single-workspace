#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(panic_info_message)]
#![deny(warnings)]

use polyhal::instruction::Instruction;
use polyhal::debug_console::DebugConsole;
use buddy_system_allocator::LockedHeap;
use core::panic::PanicInfo;
use log::*;
#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();
//The entry point
#[polyhal::arch_entry]
extern "C" fn rust_main() -> ! {
    for c in b"Hello, world!" {
        #[allow(deprecated)]
        DebugConsole::putchar(*c as _);
    }
    Instruction::shutdown();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        error!(
            "[kernel] Panicked at {}:{} {}",
            location.file(),
            location.line(),
            info.message().unwrap()
        );
    } else {
        error!("[kernel] Panicked: {}", info.message().unwrap());
    }
    Instruction::shutdown()
}