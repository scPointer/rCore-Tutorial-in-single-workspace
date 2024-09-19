use crate::PROCESSOR;
use alloc::sync::Arc;
use alloc::{alloc::alloc_zeroed, boxed::Box, vec::Vec};
use kernel_vm::MemorySet;
use polyhal::kcontext::{read_current_tp, KContext, KContextArgs};
use polyhal::trapframe::{TrapFrame, TrapFrameArgs};
use core::mem::size_of;
use core::{alloc::Layout, str::FromStr};
use easy_fs::FileHandle;
use rcore_task_manage::{ProcId, ThreadId};
use signal::Signal;
use signal_impl::SignalImpl;
use spin::Mutex;
use sync::{Condvar, Mutex as MutexTrait, Semaphore};
use xmas_elf::{
    header::{self, HeaderPt2, Machine},
    program, ElfFile,
};

pub const KERNEL_STACK_SIZE: usize = 4096 * 0x10;
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
/// 线程
pub struct Thread {
    /// 不可变
    pub tid: ThreadId,
    pub ppid:ProcId,
    /// 可变
    /// 可变
    pub trap_cx: TrapFrame,
    pub task_cx: KContext,
    pub kstack:KernelStack
}

impl Thread {
    pub fn new(ppid: ProcId, context: TrapFrame) -> Self {
        let kstack = KernelStack::new();
        Self {
            tid: ThreadId::new(),
            ppid,
            trap_cx:context,
            task_cx:{
                let mut context = KContext::blank();
                context[KContextArgs::KSP] = kstack.get_position().1;
                context[KContextArgs::KTP] = read_current_tp();
                context
            },
            kstack
        }
    }
}

/// 进程。
pub struct Process {
    /// 不可变
    pub pid: ProcId,
    /// 可变
    pub memory_set: MemorySet,
    /// 文件描述符表
    pub fd_table: Vec<Option<Mutex<FileHandle>>>,
    /// 信号模块
    pub signal: Box<dyn Signal>,
    pub usr_stack:usize,
    /// 分配的锁以及信号量
    pub semaphore_list: Vec<Option<Arc<Semaphore>>>,
    pub mutex_list: Vec<Option<Arc<dyn MutexTrait>>>,
    pub condvar_list: Vec<Option<Arc<Condvar>>>,
}

impl Process {
    /// 只支持一个线程
    pub fn exec(&mut self, elf: ElfFile) {
        let (proc, thread) = Process::from_elf(elf).unwrap();
        self.memory_set = proc.memory_set;
        self.usr_stack = proc.usr_stack;
        self.pid = proc.pid;
        unsafe {
            let pthreads = PROCESSOR.get_thread(self.pid).unwrap();
            PROCESSOR.get_task(pthreads[0]).unwrap().task_cx = thread.task_cx;
            PROCESSOR.get_task(pthreads[0]).unwrap().trap_cx = thread.trap_cx;
            PROCESSOR.get_task(pthreads[0]).unwrap().ppid = thread.ppid;
            PROCESSOR.get_task(pthreads[0]).unwrap().tid = thread.tid;

        }
    }
    /// 只支持一个线程
    pub fn fork(&mut self) -> Option<(Self, Thread)> {
        // 子进程 pid
        let pid = ProcId::new();
        // 复制父进程地址空间
        let parent_addr_space = &self.memory_set;
        let mut address_space = MemorySet::from_existed_user(parent_addr_space);
        // 线程
        let pthreads = unsafe { PROCESSOR.get_thread(self.pid).unwrap() };
        let context = unsafe {
            PROCESSOR
                .get_task(pthreads[0])
                .unwrap()
                .trap_cx
                .clone()
        };
        let thread: Thread = Thread::new(pid, context);
        // 复制父进程文件符描述表
        let mut new_fd_table: Vec<Option<Mutex<FileHandle>>> = Vec::new();
        for fd in self.fd_table.iter_mut() {
            if let Some(file) = fd {
                new_fd_table.push(Some(Mutex::new(file.get_mut().clone())));
            } else {
                new_fd_table.push(None);
            }
        }
        println!("3335");
        let res =(
            Self {
                pid,
                memory_set:address_space,
                usr_stack:self.usr_stack,
                fd_table: new_fd_table,
                signal: self.signal.from_fork(),
                semaphore_list: Vec::new(),
                mutex_list: Vec::new(),
                condvar_list: Vec::new(),
            },
            thread,
        );
        println!("777");
        Some(res)
        // None
    }

    pub fn from_elf(elf: ElfFile) -> Option<(Self, Thread)> {
        let (memory_set, user_sp, entry_point) = MemorySet::from_elf(elf);    
        let kstack = KernelStack::new();
        // push a task context which goes to trap_return to the top of kernel stack
        let mut process = Self {
            pid:ProcId::new(),
            memory_set,
            fd_table:vec![
                // Stdin
                Some(Mutex::new(FileHandle::empty(true, false))),
                // Stdout
                Some(Mutex::new(FileHandle::empty(false, true))),
            ],
            usr_stack:user_sp,
            signal: Box::new(SignalImpl::new()),
            semaphore_list: Vec::new(),
            mutex_list: Vec::new(),
            condvar_list: Vec::new(),
        };
        let mut ctx = TrapFrame::new();
        ctx[TrapFrameArgs::SEPC]=entry_point;

        ctx[TrapFrameArgs::SP]=user_sp;
        let mut thread = Thread::new(process.pid, ctx);
        Some((process,thread))
    }
}
