use polyhal::{consts::VIRT_ADDR_START, trap::{run_user_task, EscapeReason}, trapframe::{TrapFrame, TrapFrameArgs}};
use syscall::{Caller, SyscallId};

/// 任务控制块。
///
/// 包含任务的上下文、状态和资源。
pub struct TaskControlBlock {
    ctx: TrapFrame,
    pub finish: bool,
    pub stack: [usize; 256],
}

/// 调度事件。
pub enum SchedulingEvent {
    None,
    Yield,
    Exit(usize),
    UnsupportedSyscall(SyscallId),
}

impl TaskControlBlock {
    pub fn zero()-> Self {
        TaskControlBlock{
        ctx: TrapFrame::new(),
        finish: false,
        stack: [0; 256],
        }
    }

    /// 初始化一个任务。
    pub fn init(&mut self, entry: usize) {
        self.stack.fill(0);
        self.finish = false;
        self.ctx = {
            let mut ctx =TrapFrame::new();
            ctx[TrapFrameArgs::SEPC] = entry;
            ctx[TrapFrameArgs::SP] = self.stack.as_ptr() as usize - VIRT_ADDR_START + core::mem::size_of_val(&self.stack);
            ctx
        };
    }

    /// 执行此任务。
    #[inline]
    pub fn execute(&mut self)->EscapeReason {
        run_user_task(&mut self.ctx)
    }

    /// 处理系统调用，返回是否应该终止程序。
    pub fn handle_syscall(&mut self) -> SchedulingEvent {
        use syscall::{SyscallId as Id, SyscallResult as Ret};
        use SchedulingEvent as Event;
        let args = self.ctx.args();
        let id = self.ctx[TrapFrameArgs::SYSCALL].into();
        match syscall::handle(Caller { entity: 0, flow: 0 }, id, args) {
            Ret::Done(ret) => match id {
                Id::EXIT => Event::Exit(self.ctx[TrapFrameArgs::ARG0]),
                Id::SCHED_YIELD => {
                    self.ctx[TrapFrameArgs::ARG0] = ret as _;
                    self.ctx[TrapFrameArgs::SEPC] += 4;
                    Event::Yield
                }
                _ => {
                    self.ctx[TrapFrameArgs::ARG0] = ret as _;
                    self.ctx[TrapFrameArgs::SEPC] += 4;
                    Event::None
                }
            },
            Ret::Unsupported(_) => Event::UnsupportedSyscall(id),
        }
    }
}
