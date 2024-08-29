//! 内存分配。

#![no_std]
#![deny(warnings, missing_docs)]

extern crate alloc;
use buddy_system_allocator::LockedHeap;


#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap = LockedHeap::empty();
const KERNEL_HEAP_SIZE: usize = 0x200_0000;
static mut HEAP_SPACE: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];
/// 初始化内存分配。
///
/// 参数 `base_address` 表示动态内存区域的起始位置。
#[inline]
pub fn init_heap() {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP_SPACE.as_ptr() as usize, KERNEL_HEAP_SIZE);
    }
}


