#[cfg(windows)]
mod platform
{
    use std::ffi::c_void;
    use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::Child;
    use std::sync::Arc;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime
    {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    extern "system"
    {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn GetProcessTimes(process: *mut c_void, creation: *mut FileTime, exit: *mut FileTime, kernel: *mut FileTime, user: *mut FileTime) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
        fn GetLastError() -> u32;
        fn WaitForSingleObject(process: *mut c_void, milliseconds: u32) -> u32;
        fn TerminateProcess(process: *mut c_void, code: u32) -> i32;
        fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
        fn SetEvent(event: *mut c_void) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system"
    {
        fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
        fn GetTokenInformation(token: *mut c_void, class: u32, data: *mut c_void, size: u32, returned: *mut u32) -> i32;
    }

    pub fn ensure_unelevated_renderer() -> Result<(), String>
    {
        let mut raw = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut raw) } == 0
        {
            return Err("cannot verify renderer process token".to_string());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut elevated = 0u32;
        let mut returned = 0u32;
        if unsafe { GetTokenInformation(token.as_raw_handle(), 20, (&mut elevated as *mut u32).cast(), 4, &mut returned) } == 0
        {
            return Err("cannot verify renderer elevation state".to_string());
        }
        if elevated != 0
        {
            return Err("Run the desktop shell without elevation. Elevated capture is available through the native CLI.".to_string());
        }
        Ok(())
    }

    fn creation_time(process: *mut c_void) -> u64
    {
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        if unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) } == 0
        {
            return 0;
        }
        ((creation.high as u64) << 32) | creation.low as u64
    }

    pub fn current_creation_time() -> u64
    {
        creation_time(unsafe { GetCurrentProcess() })
    }

    pub fn signal_cancel_event(name: &str) -> Result<(), u32>
    {
        if !name.starts_with("Local\\KNMonCancel_") || name.contains('\0') || name.encode_utf16().count() >= 128
        {
            return Err(87);
        }
        let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        let raw = unsafe { OpenEventW(2, 0, wide.as_ptr()) };
        if raw.is_null()
        {
            return Err(unsafe { GetLastError() });
        }
        let event = unsafe { OwnedHandle::from_raw_handle(raw) };
        if unsafe { SetEvent(event.as_raw_handle()) } == 0
        {
            return Err(unsafe { GetLastError() });
        }
        Ok(())
    }

    #[derive(Debug, Clone)]
    pub struct RetainedProcess
    {
        handle: Arc<OwnedHandle>,
        pub process_id: u32,
        pub creation_time: u64,
    }

    impl RetainedProcess
    {
        pub fn from_child(child: &Child) -> Result<Self, String>
        {
            let handle = child.as_handle().try_clone_to_owned().map_err(|e| e.to_string())?;
            let creation_time = creation_time(handle.as_raw_handle());
            if creation_time == 0
            {
                return Err("helper process creation time unavailable".to_string());
            }
            Ok(Self { handle: Arc::new(handle), process_id: child.id(), creation_time })
        }

        pub fn open_identified(pid: u32, expected_creation: u64, terminate: bool) -> Result<Self, u32>
        {
            if pid == 0 || expected_creation == 0 || (terminate && pid == std::process::id())
            {
                return Err(87);
            }
            let access = 0x1000 | 0x00100000 | if terminate { 1 } else { 0 };
            let raw = unsafe { OpenProcess(access, 0, pid) };
            if raw.is_null()
            {
                return Err(unsafe { GetLastError() });
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
            let creation_time = creation_time(raw);
            if creation_time != expected_creation
            {
                return Err(1168);
            }
            Ok(Self { handle: Arc::new(handle), process_id: pid, creation_time })
        }

        pub fn alive(&self) -> bool
        {
            unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) == 258 }
        }

        pub fn terminate_owned(&self, code: u32) -> Result<(), u32>
        {
            if !self.alive()
            {
                return Ok(());
            }
            if unsafe { TerminateProcess(self.handle.as_raw_handle(), code) } == 0
            {
                return Err(unsafe { GetLastError() });
            }
            if unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 5000) } != 0
            {
                return Err(258);
            }
            Ok(())
        }
    }

    pub fn is_process_alive(pid: u32) -> bool
    {
        let raw = unsafe { OpenProcess(0x1000 | 0x00100000, 0, pid) };
        if raw.is_null()
        {
            return false;
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) == 258 }
    }
}

#[cfg(not(windows))]
mod platform
{
    #[derive(Debug, Clone)]
    pub struct RetainedProcess
    {
        pub process_id: u32,
        pub creation_time: u64,
    }
    impl RetainedProcess
    {
        pub fn from_child(_child: &std::process::Child) -> Result<Self, String>
        {
            Err("native process ownership requires Windows".to_string())
        }
        pub fn open_identified(_pid: u32, _created: u64, _terminate: bool) -> Result<Self, u32>
        {
            Err(50)
        }
        pub fn alive(&self) -> bool
        {
            false
        }
        pub fn terminate_owned(&self, _code: u32) -> Result<(), u32>
        {
            Err(50)
        }
    }
    pub fn current_creation_time() -> u64
    {
        0
    }
    pub fn ensure_unelevated_renderer() -> Result<(), String>
    {
        Ok(())
    }
    pub fn signal_cancel_event(_name: &str) -> Result<(), u32>
    {
        Err(50)
    }
    pub fn is_process_alive(_pid: u32) -> bool
    {
        false
    }
}

pub use platform::*;
