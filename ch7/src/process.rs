use alloc::{alloc::alloc_zeroed, boxed::Box, sync::Arc, vec::Vec};
use kernel_vm::MemorySet;
use polyhal::{kcontext::{read_current_tp, KContext, KContextArgs}, trapframe::{TrapFrame, TrapFrameArgs}};
use core::{alloc::Layout, mem::size_of, str::FromStr};
use easy_fs::FileHandle;
use rcore_task_manage::ProcId;
use signal::Signal;
use signal_impl::SignalImpl;
use spin::Mutex;
use xmas_elf::{
    header::{self, HeaderPt2, Machine},
    program, ElfFile,
};

pub const KERNEL_STACK_SIZE: usize = 4096 * 2;
pub struct KernelStack {
    inner: Arc<[u128; KERNEL_STACK_SIZE / size_of::<u128>()]>,
}

impl KernelStack {
    pub fn new() -> Self {
        Self {
            inner: Arc::new([0u128; KERNEL_STACK_SIZE / size_of::<u128>()]),
        }
    }

    pub fn get_position(&self) -> (usize, usize) {
        let bottom = self.inner.as_ptr() as usize;
        (bottom, bottom + KERNEL_STACK_SIZE)
    }
}

/// 进程。
pub struct Process {
    /// 不可变
    pub pid: ProcId,
    /// 可变
    pub trap_cx: TrapFrame,
    pub task_cx: KContext,
    pub kernel_stack: KernelStack,
    pub memory_set: MemorySet,
    /// 文件描述符表
    pub fd_table: Vec<Option<Mutex<FileHandle>>>,

    /// 信号模块
    pub signal: Box<dyn Signal>,
}

impl Process {
    pub fn exec(&mut self, elf: ElfFile) {
        let proc = Process::from_elf(elf).unwrap();
        self.memory_set = proc.memory_set;
        self.task_cx = proc.task_cx;
        self.trap_cx = proc.trap_cx;
        self.kernel_stack = proc.kernel_stack;
    }

    pub fn fork(&mut self) -> Option<Process> {
        // 子进程 pid
        let pid = ProcId::new();
        // 复制父进程地址空间
        let parent_addr_space = &self.memory_set;
        let mut address_space = MemorySet::from_existed_user(parent_addr_space);
        let kstack = KernelStack::new();
        // 复制父进程文件符描述表
        let mut new_fd_table: Vec<Option<Mutex<FileHandle>>> = Vec::new();
        for fd in self.fd_table.iter_mut() {
            if let Some(file) = fd {
                new_fd_table.push(Some(Mutex::new(file.get_mut().clone())));
            } else {
                new_fd_table.push(None);
            }
        }
        Some(Self {
            pid,
            trap_cx: self.trap_cx.clone(),
            task_cx: {
                let mut context = KContext::blank();
                context[KContextArgs::KSP] = kstack.get_position().1;
                context[KContextArgs::KTP] = read_current_tp();
                context
            },
            kernel_stack:kstack,
            memory_set:address_space,
            fd_table: new_fd_table,
            signal: self.signal.from_fork(),
        })
    }

    pub fn from_elf(elf: ElfFile) -> Option<Self> {
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf);       
        let kstack = KernelStack::new();
        // push a task context which goes to trap_return to the top of kernel stack
        let mut process = Self {
            pid:ProcId::new(),
            trap_cx: TrapFrame::new(),
            task_cx: {
                let mut context = KContext::blank();
                context[KContextArgs::KSP] = kstack.get_position().1;
                context[KContextArgs::KTP] = read_current_tp();
                context
            },
            kernel_stack:kstack,
            memory_set,
            fd_table:vec![
                // Stdin
                Some(Mutex::new(FileHandle::empty(true, false))),
                // Stdout
                Some(Mutex::new(FileHandle::empty(false, true))),
            ],
            signal: Box::new(SignalImpl::new()),
        };
        // prepare TrapContext in user space
        process.trap_cx[TrapFrameArgs::SEPC] = entry_point;
        process.trap_cx[TrapFrameArgs::SP] = user_sp;
        Some(process)
    }
}
