extern crate libc;

use std::mem;
use std::num::NonZeroUsize;

const PROC_TASKINFO_SIZE: usize = mem::size_of::<libc::proc_taskinfo>();

pub(crate) fn num_threads() -> Option<NonZeroUsize> {
    let mut pti: libc::proc_taskinfo = unsafe { mem::zeroed() };

    let result = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            &mut pti as *mut libc::proc_taskinfo as *mut libc::c_void,
            PROC_TASKINFO_SIZE as libc::c_int,
        )
    };

    if result == PROC_TASKINFO_SIZE as libc::c_int {
        return NonZeroUsize::new(pti.pti_threadnum as usize);
    }

    None
}
