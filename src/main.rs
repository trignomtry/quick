use crate::TokenKind::*;
use clap::Parser as Clap;
unsafe extern "C" {
    fn strcmp(a: *const i8, b: *const i8) -> i32;
    fn strncmp(a: *const i8, b: *const i8, c: i32) -> i32;
    fn printf(fmt: *const i8, ...) -> i32;
    fn malloc(size: usize) -> *mut std::ffi::c_void;

    fn strcpy(dest: *mut i8, src: *const i8) -> *mut i8;
    fn sprintf(buf: *mut i8, fmt: *const i8, ...) -> i32;
    fn strcat(dest: *mut i8, src: *const i8) -> *mut i8;
    fn strlen(s: *const i8) -> usize;
    fn atoi(s: *const i8) -> usize;
    // Correct strstr signature: returns pointer to match or NULL
    fn strstr(s: *const i8, o: *const i8) -> *mut i8;

    fn rand() -> i32;
    fn time(t: *mut i64) -> i64;
    fn srand(seed: u32);
    fn fdopen(fd: i32, mode: *const i8) -> *mut std::ffi::c_void;
    fn fopen(filename: *const i8, mode: *const i8) -> *mut std::ffi::c_void;
    fn fwrite(
        ptr: *const std::ffi::c_void,
        size: usize,
        count: usize,
        stream: *mut std::ffi::c_void,
    ) -> usize;
    fn fread(
        ptr: *mut std::ffi::c_void,
        size: usize,
        count: usize,
        stream: *mut std::ffi::c_void,
    ) -> usize;
    fn fclose(stream: *mut std::ffi::c_void) -> i32;
    fn fgets(s: *mut i8, size: i32, stream: *mut std::ffi::c_void) -> *mut i8;
    fn realloc(ptr: *mut std::ffi::c_void, size: usize) -> *mut std::ffi::c_void;
    fn LLVMLinkInMCJIT();
    fn LLVMLinkInInterpreter();

}

#[unsafe(no_mangle)]
pub extern "C" fn get_stdin() -> *mut std::ffi::c_void {
    unsafe {
        // Use fd 0 (STDIN) opened as a FILE* via fdopen("r")
        let mode = b"r\0";
        fdopen(0, mode.as_ptr() as *const i8)
    }
}
// ───── Minimal KV Object Runtime (string -> string) ─────
// Fast baseline using std HashMap; can swap to ahash/hashbrown later
struct KvMap {
    inner: HashMap<String, *mut c_void>,
}

#[derive(Clone)]
struct CaptureDescriptor<'ctx> {
    global_name: String,
    ty: BasicTypeEnum<'ctx>,
}

struct FunctionScopeGuard<'a> {
    stack: &'a RefCell<Vec<String>>,
}

impl<'a> FunctionScopeGuard<'a> {
    fn new(stack: &'a RefCell<Vec<String>>, name: String) -> Self {
        stack.borrow_mut().push(name);
        Self { stack }
    }
}

impl<'a> Drop for FunctionScopeGuard<'a> {
    fn drop(&mut self) {
        let _ = self.stack.borrow_mut().pop();
    }
}

#[derive(Clone)]
struct LoopContext<'ctx> {
    break_block: BasicBlock<'ctx>,
    _continue_block: BasicBlock<'ctx>,
}

struct LoopScopeGuard<'a, 'ctx> {
    stack: &'a RefCell<Vec<LoopContext<'ctx>>>,
}

impl<'a, 'ctx> LoopScopeGuard<'a, 'ctx> {
    fn new(stack: &'a RefCell<Vec<LoopContext<'ctx>>>, ctx: LoopContext<'ctx>) -> Self {
        stack.borrow_mut().push(ctx);
        Self { stack }
    }
}

impl<'a, 'ctx> Drop for LoopScopeGuard<'a, 'ctx> {
    fn drop(&mut self) {
        let _ = self.stack.borrow_mut().pop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn qs_obj_new() -> *mut c_void {
    let m = KvMap {
        inner: HashMap::new(),
    };
    Box::into_raw(Box::new(m)) as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_obj_insert_str(map: *mut c_void, key: *const c_char, val: *mut c_void) {
    if map.is_null() || key.is_null() {
        return;
    }
    let m = &mut *(map as *mut KvMap);
    // Key stays as Rust String for hashing; value is stored as an opaque pointer
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    m.inner.insert(k, val);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_obj_get_str(map: *mut c_void, key: *const c_char) -> *mut c_void {
    if map.is_null() || key.is_null() {
        return std::ptr::null_mut();
    }
    let m = &mut *(map as *mut KvMap);
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    match m.inner.get(&k) {
        Some(ptr) => *ptr,
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_str_replace(
    haystack: *const c_char,
    needle: *const c_char,
    replacement: *const c_char,
) -> *mut c_char {
    if haystack.is_null() {
        return std::ptr::null_mut();
    }

    let hay_bytes = CStr::from_ptr(haystack).to_bytes();
    let needle_bytes = if needle.is_null() {
        &[][..]
    } else {
        CStr::from_ptr(needle).to_bytes()
    };
    let replacement_bytes = if replacement.is_null() {
        &[][..]
    } else {
        CStr::from_ptr(replacement).to_bytes()
    };

    if needle_bytes.is_empty() {
        return std::ffi::CString::new(hay_bytes.to_vec())
            .unwrap()
            .into_raw();
    }

    let needle_len = needle_bytes.len();
    let mut result = Vec::with_capacity(hay_bytes.len());
    let mut index = 0;
    let hay_len = hay_bytes.len();
    while index < hay_len {
        if index + needle_len <= hay_len && &hay_bytes[index..index + needle_len] == needle_bytes {
            result.extend_from_slice(replacement_bytes);
            index += needle_len;
        } else {
            result.push(hay_bytes[index]);
            index += 1;
        }
    }

    std::ffi::CString::new(result).unwrap().into_raw()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_str_split(
    haystack: *const c_char,
    delimiter: *const c_char,
) -> *mut c_void {
    let hay_bytes = if haystack.is_null() {
        &[][..]
    } else {
        CStr::from_ptr(haystack).to_bytes()
    };
    let delim_bytes = if delimiter.is_null() {
        &[][..]
    } else {
        CStr::from_ptr(delimiter).to_bytes()
    };

    let mut segments: Vec<Vec<u8>> = Vec::new();

    if delim_bytes.is_empty() {
        segments.push(hay_bytes.to_vec());
    } else {
        let mut start = 0usize;
        let mut index = 0usize;
        while index + delim_bytes.len() <= hay_bytes.len() {
            if &hay_bytes[index..index + delim_bytes.len()] == delim_bytes {
                segments.push(hay_bytes[start..index].to_vec());
                index += delim_bytes.len();
                start = index;
            } else {
                index += 1;
            }
        }
        segments.push(hay_bytes[start..].to_vec());
    }

    let mut c_strings: Vec<*mut c_void> = Vec::with_capacity(segments.len());
    for seg in segments {
        let c = std::ffi::CString::new(seg).unwrap();
        c_strings.push(c.into_raw() as *mut c_void);
    }

    let slots = c_strings.len() + 1;
    let total_bytes = slots * std::mem::size_of::<*mut c_void>();
    let buffer = malloc(total_bytes);
    if buffer.is_null() {
        for ptr in c_strings {
            let _ = std::ffi::CString::from_raw(ptr as *mut c_char);
        }
        return std::ptr::null_mut();
    }

    // First slot stores the length as f64
    let len_ptr = buffer.cast::<f64>();
    *len_ptr = c_strings.len() as f64;

    // Remaining slots store string pointers
    let data_ptr = buffer.cast::<*mut c_void>().add(1);
    for (idx, ptr) in c_strings.into_iter().enumerate() {
        data_ptr.add(idx).write(ptr);
    }

    buffer
}
use hyper::body::Body;
use inkwell::AddressSpace;
use inkwell::OptimizationLevel;
use inkwell::basic_block::BasicBlock;
use inkwell::builder::{Builder, BuilderError};
use inkwell::context;
use inkwell::execution_engine::{ExecutionEngine, FunctionLookupError, JitFunction};
use inkwell::module::{Linkage, Module};
use inkwell::types::{BasicType, BasicTypeEnum};
use inkwell::values::{
    BasicMetadataValueEnum, BasicValue as _, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};
use inkwell::targets::{InitializationConfig, Target};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::ops::Index;
use std::ptr;

use std::convert::Infallible;
use std::ffi::CStr;
use std::ffi::c_void;
use std::future::Future;
use std::os::raw::c_char;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

// Hyper (async HTTP server)
use hyper::service::{make_service_fn, service_fn};
use hyper::{Request as HyperRequest, Response as HyperResponse, StatusCode};

// ───── High-Performance HTTP Runtime (Actix-style) ─────

// Unique ID generator for anonymous functions to avoid name collisions
static INLINE_FN_COUNTER: AtomicUsize = AtomicUsize::new(0);
static SERVER_RUNNING: AtomicBool = AtomicBool::new(false);
static LLVM_INIT: OnceLock<()> = OnceLock::new();

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
}

// Global Tokio runtime for blocking FFI helpers when no runtime is active
static GLOBAL_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
// Dedicated server runtime to keep the HTTP server truly async and alive
static SERVER_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn block_on_in_runtime<F: Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(fut)
    } else {
        let rt = GLOBAL_RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .thread_name("qs-global-rt")
                .enable_io()
                .enable_time()
                .build()
                .expect("Failed to build global tokio runtime")
        });
        rt.block_on(fut)
    }
}

fn ensure_llvm_ready() {
    LLVM_INIT.get_or_init(|| {
        Target::initialize_native(&InitializationConfig::default())
            .expect("Failed to start the QuickScript runner");
        unsafe {
            LLVMLinkInInterpreter();
            LLVMLinkInMCJIT();
        }
    });
}

#[repr(C)]
pub struct RequestObject {
    method: *mut c_char,
    path: *mut c_char,
    query: *mut c_char,
    headers: *mut c_char,
    body: *mut c_char,
}

// Response object for structured HTTP responses
#[repr(C)]
pub struct ResponseObject {
    status_code: i32,
    content_type: *mut c_char,
    body: *mut c_char,
    headers: *mut c_char,
}

// Web helper struct for creating responses
#[repr(C)]
pub struct WebHelper {
    _dummy: u8, // Zero-sized structs aren't allowed in C ABI
}

#[repr(C)]
pub struct RangeBuilder {
    from: f64,
    to: f64,
    step: f64,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_request_object(
    method: *const c_char,
    path: *const c_char,
    query: *const c_char,
    headers: *const c_char,
    body: *const c_char,
) -> *mut RequestObject {
    let request = Box::new(RequestObject {
        method: if method.is_null() {
            std::ptr::null_mut()
        } else {
            unsafe {
                let s = CStr::from_ptr(method).to_string_lossy();
                let c_str = std::ffi::CString::new(s.as_ref()).unwrap();
                c_str.into_raw()
            }
        },
        path: if path.is_null() {
            std::ptr::null_mut()
        } else {
            unsafe {
                let s = CStr::from_ptr(path).to_string_lossy();
                let c_str = std::ffi::CString::new(s.as_ref()).unwrap();
                c_str.into_raw()
            }
        },
        query: if query.is_null() {
            std::ptr::null_mut()
        } else {
            unsafe {
                let s = CStr::from_ptr(query).to_string_lossy();
                let c_str = std::ffi::CString::new(s.as_ref()).unwrap();
                c_str.into_raw()
            }
        },
        headers: if headers.is_null() {
            std::ptr::null_mut()
        } else {
            unsafe {
                let s = CStr::from_ptr(headers).to_string_lossy();
                let c_str = std::ffi::CString::new(s.as_ref()).unwrap();
                c_str.into_raw()
            }
        },
        body: if body.is_null() || unsafe { CStr::from_ptr(body) }.is_empty() {
            std::ptr::null_mut()
        } else {
            unsafe {
                let s = CStr::from_ptr(body).to_string_lossy();
                let c_str = std::ffi::CString::new(s.as_ref()).unwrap();
                c_str.into_raw()
            }
        },
    });
    Box::into_raw(request)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_request_method(request: *const RequestObject) -> *const c_char {
    if request.is_null() {
        return std::ptr::null();
    }
    unsafe { (*request).method }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_request_path(request: *const RequestObject) -> *const c_char {
    if request.is_null() {
        return std::ptr::null();
    }
    unsafe { (*request).path }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_request_body(request: *const RequestObject) -> *const c_char {
    if request.is_null() {
        return std::ptr::null();
    }
    unsafe { (*request).body }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_request_query(request: *const RequestObject) -> *const c_char {
    if request.is_null() {
        return std::ptr::null();
    }
    unsafe { (*request).query }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_request_headers(request: *const RequestObject) -> *const c_char {
    if request.is_null() {
        return std::ptr::null();
    }
    unsafe { (*request).headers }
}

// Global storage for callback function pointer
static CALLBACK_HANDLER: OnceLock<usize> = OnceLock::new();

// ───── Web Helper Functions ─────

#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_web_helper() -> *mut WebHelper {
    Box::into_raw(Box::new(WebHelper { _dummy: 0 }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_range_builder() -> *mut RangeBuilder {
    Box::into_raw(Box::new(RangeBuilder {
        from: 0.0,
        to: 0.0,
        step: 1.0,
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_to(buil: *mut RangeBuilder, tua: f64) -> *mut RangeBuilder {
    if buil.is_null() {
        return Box::into_raw(Box::new(RangeBuilder {
            from: 0.0,
            to: tua,
            step: 1.0,
        }));
    }
    (*buil).to = tua;
    buil
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_from(
    buil: *mut RangeBuilder,
    tua: f64,
) -> *mut RangeBuilder {
    if buil.is_null() {
        return Box::into_raw(Box::new(RangeBuilder {
            from: tua,
            to: 0.0,
            step: 1.0,
        }));
    }
    (*buil).from = tua;
    buil
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_step(
    buil: *mut RangeBuilder,
    tua: f64,
) -> *mut RangeBuilder {
    if buil.is_null() {
        return Box::into_raw(Box::new(RangeBuilder {
            from: 0.0,
            to: 0.0,
            step: if tua == 0.0 { 1.0 } else { tua },
        }));
    }
    if tua == 0.0 {
        (*buil).step = 1.0;
    } else {
        (*buil).step = tua;
    }
    buil
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_get_from(buil: *const RangeBuilder) -> f64 {
    if buil.is_null() {
        return 0.0;
    }
    (*buil).from
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_get_to(buil: *const RangeBuilder) -> f64 {
    if buil.is_null() {
        return 0.0;
    }
    (*buil).to
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_get_step(buil: *const RangeBuilder) -> f64 {
    if buil.is_null() {
        return 1.0;
    }
    let step = (*buil).step;
    if step == 0.0 { 1.0 } else { step }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_text(content: *const c_char) -> *mut ResponseObject {
    let content_str = if content.is_null() {
        String::new()
    } else {
        unsafe { cstr_to_string(content) }
    };

    let response = Box::new(ResponseObject {
        status_code: 200,
        content_type: std::ffi::CString::new("text/plain; charset=utf-8")
            .unwrap()
            .into_raw(),
        body: std::ffi::CString::new(content_str).unwrap().into_raw(),
        headers: std::ffi::CString::new("").unwrap().into_raw(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_json(content: *const c_char) -> *mut ResponseObject {
    let content_str = if content.is_null() {
        String::new()
    } else {
        unsafe { cstr_to_string(content) }
    };

    let response = Box::new(ResponseObject {
        status_code: 200,
        content_type: std::ffi::CString::new("application/json; charset=utf-8")
            .unwrap()
            .into_raw(),
        body: std::ffi::CString::new(content_str).unwrap().into_raw(),
        headers: std::ffi::CString::new("").unwrap().into_raw(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_page(content: *const c_char) -> *mut ResponseObject {
    let content_str = if content.is_null() {
        String::new()
    } else {
        unsafe { cstr_to_string(content) }
    };

    let response = Box::new(ResponseObject {
        status_code: 200,
        content_type: std::ffi::CString::new("text/html; charset=utf-8")
            .unwrap()
            .into_raw(),
        body: std::ffi::CString::new(content_str).unwrap().into_raw(),
        headers: std::ffi::CString::new("").unwrap().into_raw(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_error_text(
    status_code: i32,
    content: *const c_char,
) -> *mut ResponseObject {
    let content_str = if content.is_null() {
        String::new()
    } else {
        unsafe { cstr_to_string(content) }
    };

    let response = Box::new(ResponseObject {
        status_code,
        content_type: std::ffi::CString::new("text/plain; charset=utf-8")
            .unwrap()
            .into_raw(),
        body: std::ffi::CString::new(content_str).unwrap().into_raw(),
        headers: std::ffi::CString::new("").unwrap().into_raw(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_error_page(
    status_code: i32,
    content: *const c_char,
) -> *mut ResponseObject {
    let content_str = if content.is_null() {
        String::new()
    } else {
        unsafe { cstr_to_string(content) }
    };

    let response = Box::new(ResponseObject {
        status_code,
        content_type: std::ffi::CString::new("text/html; charset=utf-8")
            .unwrap()
            .into_raw(),
        body: std::ffi::CString::new(content_str).unwrap().into_raw(),
        headers: std::ffi::CString::new("").unwrap().into_raw(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_redirect(
    location: *const c_char,
    permanent: bool,
) -> *mut ResponseObject {
    let location_str = if location.is_null() {
        String::from("/")
    } else {
        unsafe { cstr_to_string(location) }
    };

    let status_code = if permanent { 301 } else { 302 };
    let headers = format!("Location: {}", location_str);

    let response = Box::new(ResponseObject {
        status_code,
        content_type: std::ffi::CString::new("text/plain; charset=utf-8")
            .unwrap()
            .into_raw(),
        body: std::ffi::CString::new("").unwrap().into_raw(),
        headers: std::ffi::CString::new(headers).unwrap().into_raw(),
    });
    Box::into_raw(response)
}

// Async file reading function for io.read() - now the default
#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_read_file(filename: *const c_char) -> *mut c_char {
    if filename.is_null() {
        return std::ptr::null_mut();
    }

    let filename_str = unsafe { cstr_to_string(filename) };

    let read_result = block_on_in_runtime(async { tokio::fs::read_to_string(&filename_str).await });

    match read_result {
        Ok(content) => std::ffi::CString::new(content).unwrap().into_raw(),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                std::ptr::null_mut()
            } else {
                std::ffi::CString::new(String::new()).unwrap().into_raw()
            }
        }
    }
}

// Async file writing function for io.write() - now the default
#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_write_file(filename: *const c_char, content: *const c_char) -> f64 {
    if filename.is_null() || content.is_null() {
        return 0.0; // failure
    }

    let filename_str = unsafe { cstr_to_string(filename) };
    let content_str = unsafe { cstr_to_string(content) };

    block_on_in_runtime(async {
        match tokio::fs::write(&filename_str, &content_str).await {
            Ok(_) => 1.0,
            Err(_) => 0.0,
        }
    })
}

// MIME type detection based on file extension
fn get_mime_type(filename: &str) -> &'static str {
    let extension = filename.split('.').last().unwrap_or("").to_lowercase();
    match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

// Serve static files with proper MIME types (sync FFI ABI)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_file(filename: *const c_char) -> *mut ResponseObject {
    if filename.is_null() {
        return unsafe { web_error_text(404, b"File not found\0".as_ptr() as *const c_char) };
    }

    let mut filename_str = unsafe { cstr_to_string(filename) };
    if filename_str.ends_with("/") {
        filename_str.push_str("index.html");
    }

    // Read file contents using the runtime helper, but expose a sync C ABI
    let read_result = block_on_in_runtime(async { tokio::fs::read_to_string(&filename_str).await });

    match read_result {
        Ok(content) => {
            let mime_type = get_mime_type(&filename_str);
            let response = Box::new(ResponseObject {
                status_code: 200,
                content_type: std::ffi::CString::new(mime_type).unwrap().into_raw(),
                body: std::ffi::CString::new(content).unwrap().into_raw(),
                headers: std::ffi::CString::new("").unwrap().into_raw(),
            });
            Box::into_raw(response)
        }
        Err(_) => unsafe { web_error_text(404, b"File not found\0".as_ptr() as *const c_char) },
    }
}

// Helper to get response fields
#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_response_status(response: *const ResponseObject) -> i32 {
    if response.is_null() {
        return 500;
    }
    unsafe { (*response).status_code }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_response_content_type(
    response: *const ResponseObject,
) -> *const c_char {
    if response.is_null() {
        return std::ptr::null();
    }
    unsafe { (*response).content_type }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_response_body(response: *const ResponseObject) -> *const c_char {
    if response.is_null() {
        return std::ptr::null();
    }
    unsafe { (*response).body }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_response_headers(response: *const ResponseObject) -> *const c_char {
    if response.is_null() {
        return std::ptr::null();
    }
    unsafe { (*response).headers }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_listen_with_callback(port: i32, callback: *const c_void) {
    let addr = format!("0.0.0.0:{port}");
    let callback_addr = callback as usize;

    // Store the callback function pointer
    CALLBACK_HANDLER
        .set(callback_addr)
        .expect("Callback already set");

    if std::env::var("QS_TEST_REQUEST").is_ok() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("failed to build test runtime");
        let request = HyperRequest::builder()
            .method("GET")
            .uri("http://localhost/trignomtry")
            .body(Body::empty())
            .expect("failed to build request");
        for n in 0..2 {
            let request = HyperRequest::builder()
                .method("GET")
                .uri("http://localhost/trignomtry")
                .body(Body::empty())
                .expect("failed to build request");
            let response = rt
                .block_on(handle_hyper_request(request, callback_addr))
                .expect("handler error");
            eprintln!("test handler #{} status: {}", n + 1, response.status());
        }
        return;
    }

    // Use same runtime configuration as original
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let worker_threads = (cpu_count * 2).min(16);

    // Build task that runs a Hyper server
    let server_task = async move {
        eprintln!("HTTP server starting on http://{addr}");
        let socket_addr: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Invalid bind address {addr}: {e}");
                return;
            }
        };
        SERVER_RUNNING.store(true, Ordering::Relaxed);

        let make_svc = make_service_fn(move |_conn| {
            let handler_addr = callback_addr;
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle_hyper_request(req, handler_addr)
                }))
            }
        });

        if let Err(e) = hyper::Server::bind(&socket_addr).serve(make_svc).await {
            eprintln!("Server error: {e}");
        }
    };

    // If we're already inside a Tokio runtime, spawn directly.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(server_task);
        return;
    }

    // Otherwise, spin up (or reuse) a dedicated multi-thread runtime and spawn the server
    let rt = SERVER_RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .thread_name("qs-worker")
            .thread_stack_size(2 * 1024 * 1024)
            .enable_io()
            .enable_time()
            .build()
            .expect("Failed to build server runtime")
    });
    rt.spawn(server_task);
}

async fn handle_hyper_request(
    req: HyperRequest<Body>,
    handler_addr: usize,
) -> Result<HyperResponse<Body>, Infallible> {
    // Method and path
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let raw_query = uri.query().unwrap_or("").to_string();

    // Percent-decode util
    fn percent_decode(input: &str) -> String {
        let bytes = input.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b'%' if i + 2 < bytes.len() => {
                    let h1 = bytes[i + 1] as char;
                    let h2 = bytes[i + 2] as char;
                    if let (Some(v1), Some(v2)) = (h1.to_digit(16), h2.to_digit(16)) {
                        out.push(((v1 << 4) as u8) | (v2 as u8));
                        i += 3;
                    } else {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    // Normalize query (decode and join)
    let query = if raw_query.is_empty() {
        String::new()
    } else {
        let mut parts = Vec::new();
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            parts.push(format!("{}={}", percent_decode(k), percent_decode(v)));
        }
        parts.join("&")
    };

    // Headers: fold into Key: Value\r\n
    let mut headers_raw = String::new();
    for (name, value) in req.headers().iter() {
        let val = value.to_str().unwrap_or("");
        headers_raw.push_str(name.as_str());
        headers_raw.push_str(": ");
        headers_raw.push_str(val);
        headers_raw.push_str("\r\n");
    }

    // Body (collect)
    let whole = match hyper::body::to_bytes(req.into_body()).await {
        Ok(b) => b,
        Err(_) => Default::default(),
    };
    let body_str = String::from_utf8(whole.to_vec()).unwrap_or_default();

    // Call the user callback on a blocking thread via FFI
    let (status_code, content_type, body, extra_headers) =
        match tokio::task::spawn_blocking(move || unsafe {
            let method_cstr = std::ffi::CString::new(method).unwrap();
            let path_cstr = std::ffi::CString::new(path).unwrap();
            let query_cstr = std::ffi::CString::new(query)
                .unwrap_or_else(|_| std::ffi::CString::new("").unwrap());
            let headers_cstr = std::ffi::CString::new(headers_raw)
                .unwrap_or_else(|_| std::ffi::CString::new("").unwrap());
            let body_cstr = std::ffi::CString::new(body_str)
                .unwrap_or_else(|_| std::ffi::CString::new("").unwrap());

            let request_obj = create_request_object(
                method_cstr.as_ptr(),
                path_cstr.as_ptr(),
                query_cstr.as_ptr(),
                headers_cstr.as_ptr(),
                body_cstr.as_ptr(),
            );

            let func: extern "C" fn(*const RequestObject) -> *mut ResponseObject =
                std::mem::transmute::<usize, _>(handler_addr);
            let response_ptr = func(request_obj);

            let out = if response_ptr.is_null() {
                (
                    404,
                    "text/plain; charset=utf-8".to_string(),
                    "Not Found".to_string(),
                    String::new(),
                )
            } else {
                let status = get_response_status(response_ptr);
                let content_type = cstr_to_string(get_response_content_type(response_ptr));
                let body = cstr_to_string(get_response_body(response_ptr));
                let headers = cstr_to_string(get_response_headers(response_ptr));
                let _ = Box::from_raw(response_ptr);
                (status, content_type, body, headers)
            };
            let _ = Box::from_raw(request_obj);
            out
        })
        .await
        {
            Ok(r) => r,
            Err(_) => (
                500,
                "text/plain; charset=utf-8".to_string(),
                "Internal Server Error".to_string(),
                String::new(),
            ),
        };

    // Build Hyper response
    let mut builder = HyperResponse::builder()
        .status(StatusCode::from_u16(status_code as u16).unwrap_or(StatusCode::OK));
    if !content_type.is_empty() {
        builder = builder.header("Content-Type", content_type);
    }
    if !extra_headers.is_empty() {
        for line in extra_headers.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let name = k.trim();
                let val = v.trim();
                if !name.is_empty() && !val.is_empty() {
                    builder = builder.header(name, val);
                }
            }
        }
    }
    let resp = builder
        .body(Body::from(body))
        .unwrap_or_else(|_| HyperResponse::new(Body::from("Internal Server Error")));
    Ok(resp)
}

#[derive(Debug, Clone)]
struct Token {
    value: std::string::String,
    kind: TokenKind,
    line: usize,
}

impl Token {
    fn print(&self) {
        let token = self;
        if let Error(_, _) = token.kind {
            eprintln!("{}{}", token.kind, token.value);
        } else if let Str(_) = token.kind {
            println!("{} \"{}\" {}", token.kind, token.value, token.value);
        } else if let Eof = token.kind {
            println!("EOF  null");
        } else if let Num(_) = token.kind {
            println!(
                "{} {} {}",
                token.kind,
                token.value,
                format_float(&token.value)
            );
        } else {
            println!("{} {} null", token.kind, token.value);
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
enum TokenKind {
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBrack,
    RBrack,
    Star,
    Dot,
    Comma,
    Plus,
    Minus,
    AmpAmp,
    PipePipe,
    Colon,
    Semicolon,
    Equal,
    EqualEqual,
    Bang,
    BangEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    BigArrow,
    Slash,
    Str(String),
    Identifier(String),
    And,
    In,
    Object,
    Enum,
    Maybe,
    Match,
    Else,
    False,
    For,
    Fun,
    If,
    Nil,
    Or,
    Print,
    Reprint,
    Return,
    Break,
    Super,
    This,
    True,
    Let,
    While,
    Use,
    Eof,
    Num(f64),
    Error(u64, std::string::String),
}

#[derive(Debug, Clone)]
enum Unary {
    Neg,
    Not,
}

#[derive(Debug, Clone)]
enum BinOp {
    Plus,
    Minus,
    Mult,
    Div,
    And,
    Or,
    NotEq,
    EqEq,
    Greater,
    GreaterEqual,
    Less,
    LessEqual,
}

#[derive(Debug, Clone)]
enum Expr {
    Literal(Value),
    Variable(String),
    Unary(Unary, Box<Expr>),
    Call(Box<Expr>, Vec<Expr>),
    Binary(Box<Expr>, BinOp, Box<Expr>),
    Get(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    List(Vec<Expr>),
    Object(String, HashMap<String, Expr>),
    Block(Vec<Instruction>),
    Function(Vec<(String, Type)>, Type, Box<Instruction>),
}
 
impl Expr {
    fn get_type(&self, ctx: &PreCtx) -> Result<Type, String> {
        let expr = self;
        let line_hint = ctx.current_line();
        let type_error = |message: String, hint: Option<&str>| -> Result<Type, String> {
            let reset = "\x1b[0m";
            let line_color = "\x1b[1;37m";
            let error_color = "\x1b[31m";
            let tip_label_color = "\x1b[1;33m";
            let tip_color = "\x1b[36m";

            let mut text = if let Some(line) = line_hint {
                format!("{line_color}[Line {line}]:{reset} {error_color}{message}{reset}")
            } else {
                format!("{error_color}{message}{reset}")
            };
            if let Some(tip) = hint {
                if !tip.is_empty() {
                    text.push_str(&format!(
                        "\n  {tip_label_color}Tip:{reset} {tip_color}{tip}{reset}"
                    ));
                }
            }
            Err(text)
        };
        let infer_expr = |sub_expr: &Expr| ctx.with_line(line_hint, || sub_expr.get_type(ctx));
        match expr {
            Expr::Variable(v) => match ctx.var_types.get(v) {
                Some(t) => Ok(t.clone()),
                None => {
                    if let Some(l) = ctx.types.get(v) {
                        Ok(Type::Custom(l.clone()))
                    } else {
                        return type_error(
                            format!("Unknown identifier \"{v}\""),
                            Some("Declare it with `let` before using it, or ensure the spelling matches the definition."),
                        );
                    }
                }
            },
            Expr::Function(params, ret_type, _body) => {
                Ok(Type::Function(params.to_vec(), Box::new(ret_type.clone())))
            }
            Expr::Index(list, _) => match infer_expr(list)? {
                Type::List(inner) => Ok(*inner),
                Type::Str => Ok(Type::Str), // indexing a string yields a one-character string
                other => {
                    return type_error(
                        format!("Cannot index into value of type {other:?}"),
                        Some("Only lists and strings support indexing. Make sure you're indexing a list or string."),
                    )
                }
            },
            Expr::Object(name, o) => {
                // Prefer the declared object type (by name) if available.
                if let Some(Custype::Object(declared)) = ctx.types.get(name) {
                    return Ok(Type::Custom(Custype::Object(declared.clone())));
                }
                // Fallback: infer a structural object type from field expressions.
                let mut fields = HashMap::new();
                for (fname, expr) in o.iter() {
                    let field_type = infer_expr(expr)?;
                    fields.insert(fname.clone(), field_type);
                }
                Ok(Type::Custom(Custype::Object(fields)))
            }
            Expr::Literal(tk) => match tk {
                Value::Num(_) => Ok(Type::Num),
                Value::Str(_) => Ok(Type::Str),
                Value::Bool(_) => Ok(Type::Bool),
                Value::Nil => Ok(Type::Nil),
                _ => {
                    return type_error(
                        "Unsupported literal value".to_string(),
                        Some("Only numbers, strings, booleans, and nil are valid literals here."),
                    )
                }
            },
            Expr::List(l) => Ok(Type::List(if let Some(r) = l.first() {
                Box::new(infer_expr(r)?)
            } else {
                Box::new(Type::Nil)
            })),
            Expr::Unary(_, e) => infer_expr(e),
            Expr::Binary(l, op, r) => {
                let lt = infer_expr(l)?.unwrap();
                let rt = infer_expr(r)?.unwrap();
                match op {
                    BinOp::And | BinOp::Or => {
                        if lt == Type::Bool && rt == Type::Bool {
                            Ok(Type::Bool)
                        } else {
                            return type_error(
                                "Logical operators require both sides to be Bool".to_string(),
                                Some("Ensure both operands evaluate to booleans before using 'and' or 'or'."),
                            )
                        }
                    }
                    BinOp::Plus => match (&lt, &rt) {
                        (Type::Num, Type::Num) => Ok(Type::Num),
                        (Type::Str, Type::Str) => Ok(Type::Str),
                        _ => type_error(
                            "The '+' operator needs two numbers or two strings".to_string(),
                            Some("Convert values to a shared type (both Num or both Str) before adding."),
                        ),
                    },
                    BinOp::Minus | BinOp::Mult | BinOp::Div => {
                        if lt == Type::Num && rt == Type::Num {
                            Ok(Type::Num)
                        } else {
                            type_error(
                                format!("Operator {op:?} requires two numbers"),
                                Some("Cast both operands to Num or adjust the expression."),
                            )
                        }
                    }
                    BinOp::EqEq | BinOp::NotEq => Ok(Type::Bool),
                    BinOp::Greater | BinOp::Less | BinOp::GreaterEqual | BinOp::LessEqual => {
                        if lt == Type::Num && rt == Type::Num {
                            Ok(Type::Bool)
                        } else {
                            type_error(
                                format!("Operator {op:?} requires two numbers"),
                                Some("Use numeric operands, or convert values before comparing."),
                            )
                        }
                    }
                }
            }

            Expr::Get(obj, prop) => {
                // Special-case: Obj.new()
                if let Expr::Variable(name) = &**obj {
                    if name == "Obj" {
                        return match prop.as_str() {
                            // Default to Obj(Str) for now; user will refine types later
                            "new" => Ok(Type::Function(
                                vec![],
                                Box::new(Type::Kv(Box::new(Type::Nil))),
                            )),
                            other => type_error(
                                format!("Unknown Obj helper '{other}'"),
                                Some("Valid helpers are 'new' for constructing empty objects."),
                            ),
                        };
                    }
                }

                // Type-checking for field access
                let obj_type = infer_expr(obj)?;
                match obj_type {
                    Type::Kv(inner) => match prop.as_str() {
                        // If inner is Nil (unknown yet), allow first insert to pick the type
                        "insert" => {
                            let val_ty = if *inner == Type::Nil {
                                // Accept any value type on first insert; actual unification happens
                                // in call checking or statement parsing.
                                Type::Nil
                            } else {
                                *inner.clone()
                            };
                            Ok(Type::Function(
                                vec![
                                    ("key".to_string(), Type::Str),
                                    ("value".to_string(), val_ty),
                                ],
                                Box::new(Type::Nil),
                            ))
                        }
                        "get" => Ok(Type::Function(
                            vec![("key".to_string(), Type::Str)],
                            Box::new(Type::Option(inner)),
                        )),
                        other => {
                            return type_error(
                                format!("Property '{other}' not found on Obj"),
                                Some("Check the available methods: insert(key, value) and get(key)."),
                            )
                        }
                    },
                    Type::List(t) => {
                        if prop == "len" {
                            Ok(Type::Function(vec![], Box::new(Type::Num)))
                        } else if prop == "push" {
                            Ok(Type::Function(
                                vec![("pushing".to_string(), *t)],
                                Box::new(Type::Nil),
                            ))
                        } else if prop == "remove" {
                            Ok(Type::Function(
                                vec![("removing".to_string(), Type::Num)],
                                Box::new(Type::Nil),
                            ))
                        } else {
                            type_error(
                                format!("Property '{prop}' not found on list"),
                                Some("Lists expose len(), push(value), and remove(index)."),
                            )
                        }
                    }
                    Type::Io => {
                        // Special-case io properties

                        match prop.as_str() {
                            "random" => Ok(Type::Function(vec![], Box::new(Type::Num))),
                            "input" => Ok(Type::Function(
                                vec![("prompt".to_string(), Type::Str)],
                                Box::new(Type::Str),
                            )),

                            "listen" => Ok(Type::Function(
                                vec![
                                    ("port".to_string(), Type::Num),
                                    (
                                        "handler".to_string(),
                                        Type::Function(
                                            vec![(
                                                "req".to_string(),
                                                Type::Custom(Custype::Object(HashMap::new())),
                                            )],
                                            Box::new(Type::WebReturn),
                                        ),
                                    ),
                                ],
                                Box::new(Type::Nil),
                            )),
                            "range" => Ok(Type::RangeBuilder),
                            "read" => Ok(Type::Function(
                                vec![("path".to_string(), Type::Str)],
                                Box::new(Type::Option(Box::new(Type::Str))),
                            )),
                            "write" => Ok(Type::Function(
                                vec![
                                    ("path".to_string(), Type::Str),
                                    ("content".to_string(), Type::Str),
                                ],
                                Box::new(Type::Nil),
                            )),
                            "web" => Ok(Type::Function(
                                vec![],
                                Box::new(Type::Custom({
                                    let mut web_type = HashMap::new();
                                    web_type.insert(
                                        "text".to_string(),
                                        Type::Function(
                                            vec![("content".to_string(), Type::Str)],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );
                                    web_type.insert(
                                        "page".to_string(),
                                        Type::Function(
                                            vec![("content".to_string(), Type::Str)],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );
                                    web_type.insert(
                                        "file".to_string(),
                                        Type::Function(
                                            vec![("name".to_string(), Type::Str)],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );
                                    web_type.insert(
                                        "json".to_string(),
                                        Type::Function(
                                            vec![("content".to_string(), Type::Str)],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );

                                    web_type.insert(
                                        "redirect".to_string(),
                                        Type::Function(
                                            vec![
                                                ("location".to_string(), Type::Str),
                                                ("permanent".to_string(), Type::Bool),
                                            ],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );
                                    // Add error property with text method
                                    let mut error_type = HashMap::new();
                                    error_type.insert(
                                        "text".to_string(),
                                        Type::Function(
                                            vec![
                                                ("status".to_string(), Type::Num),
                                                ("content".to_string(), Type::Str),
                                            ],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );
                                    error_type.insert(
                                        "page".to_string(),
                                        Type::Function(
                                            vec![
                                                ("status".to_string(), Type::Num),
                                                ("content".to_string(), Type::Str),
                                            ],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );
                                    error_type.insert(
                                        "file".to_string(),
                                        Type::Function(
                                            vec![
                                                ("status".to_string(), Type::Num),
                                                ("name".to_string(), Type::Str),
                                            ],
                                            Box::new(Type::WebReturn),
                                        ),
                                    );
                                    web_type.insert(
                                        "error".to_string(),
                                        Type::Custom(Custype::Object(error_type)),
                                    );
                                    Custype::Object(web_type)
                                })),
                            )),
                            other => {
                                return type_error(
                                    format!("Unknown io helper '{other}'"),
                                    Some("Check the available builders like range(), read(), write(), web(), listen(), input(), and random()."),
                                )
                            }
                        }
                    }
                    Type::RangeBuilder => match prop.as_str() {
                        "to" => Ok(Type::Function(
                            vec![("rang".to_string(), Type::Num)],
                            Box::new(Type::RangeBuilder),
                        )),
                        "from" => Ok(Type::Function(
                            vec![("rang".to_string(), Type::Num)],
                            Box::new(Type::RangeBuilder),
                        )),
                        "step" => Ok(Type::Function(
                            vec![("rang".to_string(), Type::Num)],
                            Box::new(Type::RangeBuilder),
                        )),
                        other => type_error(
                            format!("Unknown range builder method '{other}'"),
                            Some("Use to(), from(), or step() when building numeric ranges."),
                        ),
                    },
                    Type::Num => match prop.as_str() {
                        "str" => Ok(Type::Function(vec![], Box::new(Type::Str))),
                        other => type_error(
                            format!("Unknown Num helper '{other}'"),
                            Some("Did you mean to call num.str()? That's the only helper currently exposed."),
                        ),
                    },
                    Type::Custom(Custype::Object(fields)) => {
                        // Look up property in custom type
                        if let Some(t) = fields.get(prop) {
                            Ok(t.clone())
                        } else {
                            type_error(
                                format!("Property '{prop}' not found on object"),
                                Some("Verify the field exists on the declared object type."),
                            )
                        }
                    }
                    Type::Custom(Custype::Enum(ref variants)) => {
                        if variants.contains(prop) {
                            Ok(obj_type)
                        } else {
                            type_error(
                                format!("Enum value does not contain variant '{prop}'"),
                                Some("Check the enum definition for available variants."),
                            )
                        }
                    }
                    Type::Str => {
                        if prop == "len" {
                            Ok(Type::Function(vec![], Box::new(Type::Num)))
                        } else if prop == "num" {
                            Ok(Type::Function(
                                vec![],
                                Box::new(Type::Option(Box::new(Type::Num))),
                            ))
                        } else if prop == "ends_with" || prop == "starts_with" {
                            Ok(Type::Function(
                                vec![("thing".to_string(), Type::Str)],
                                Box::new(Type::Bool),
                            ))
                        } else if prop == "contains" {
                            Ok(Type::Function(
                                vec![("needle".to_string(), Type::Str)],
                                Box::new(Type::Bool),
                            ))
                        } else if prop == "replace" {
                            Ok(Type::Function(
                                vec![
                                    ("needle".to_string(), Type::Str),
                                    ("replacement".to_string(), Type::Str),
                                ],
                                Box::new(Type::Str),
                            ))
                        } else if prop == "split" {
                            Ok(Type::Function(
                                vec![("delimiter".to_string(), Type::Str)],
                                Box::new(Type::List(Box::new(Type::Str))),
                            ))
                        } else {
                            type_error(
                                format!("Property '{prop}' not found on Str"),
                                Some("Available helpers: len, num, starts_with, ends_with, contains, replace, split."),
                            )
                        }
                    }
                    Type::Option(inner) => match prop.as_str() {
                        "default" => Ok(Type::Function(
                            vec![("def".to_string(), *inner.clone())],
                            inner,
                        )),
                        _ => type_error(
                            format!("Property '{prop}' not found on Option"),
                            Some("Options only expose default(value) for now."),
                        ),
                    },
                    other => type_error(
                        format!("Cannot access property '{prop}' on type {other:?}"),
                        Some("Check the value before using '.' or convert it to an object with that field."),
                    ),
                }
            }
            Expr::Block(_) => Ok(Type::Nil),
            Expr::Call(callee, args) => {
                // Special-case: io.random() always returns a number
                //             if let Expr::Get(inner, prop) = &**callee {
                // if let Expr::Variable(obj) = &**inner {
                //     if obj == "io" && prop == "random" {
                //         if args.is_empty() {
                //             return Ok(Type::Num);
                //         } else {
                //             return Err(format!(
                //                 "io.random() expects no arguments, got {}",
                //                 args.len(),
                //             ));
                //         }
                //     } else if obj == "io" && prop == "listen" {
                //         if args.len() == 1 || args.len() == 2 {
                //             return Ok(Type::Num); // io.listen returns a number
                //         } else {
                //             return Err(format!(
                //                 "io.listen() expects 1 or 2 arguments, got {}",
                //                 args.len(),
                //             ));
                //         }
                //     } else if obj == "io" && prop == "method" {
                //         if args.is_empty() {
                //             return Ok(Type::Str); // io.method() returns a string
                //         } else {
                //             return Err(format!(
                //                 "io.method() expects no arguments, got {}",
                //                 args.len(),
                //             ));
                //         }
                //     } else if obj == "io" && prop == "path" {
                //         if args.is_empty() {
                //             return Ok(Type::Str); // io.path() returns a string
                //         } else {
                //             return Err(format!(
                //                 "io.path() expects no arguments, got {}",
                //                 args.len(),
                //             ));
                //         }
                //     } else if obj == "io" && prop == "web" {
                //         if args.is_empty() {
                //             return Ok(Type::Custom({
                //                 let mut web_type = HashMap::new();
                //                 web_type.insert(
                //                     "text".to_string(),
                //                     Type::Function(
                //                         vec![("content".to_string(), Type::Str)],
                //                         Box::new(Type::WebReturn),
                //                     ),
                //                 );
                //                 web_type.insert(
                //                     "page".to_string(),
                //                     Type::Function(
                //                         vec![("content".to_string(), Type::Str)],
                //                         Box::new(Type::WebReturn),
                //                     ),
                //                 );
                //                 web_type.insert(
                //                     "file".to_string(),
                //                     Type::Function(
                //                         vec![("name".to_string(), Type::Str)],
                //                         Box::new(Type::WebReturn),
                //                     ),
                //                 );
                //                 web_type.insert(
                //                     "json".to_string(),
                //                     Type::Function(
                //                         vec![("content".to_string(), Type::Str)],
                //                         Box::new(Type::WebReturn),
                //                     ),
                //                 );

                //                 web_type.insert(
                //                     "redirect".to_string(),
                //                     Type::Function(
                //                         vec![
                //                             ("location".to_string(), Type::Str),
                //                             ("permanent".to_string(), Type::Bool),
                //                         ],
                //                         Box::new(Type::WebReturn),
                //                     ),
                //                 );
                //                 // Add error property with text method
                //                 let mut error_type = HashMap::new();
                //                 error_type.insert(
                //                     "text".to_string(),
                //                     Type::Function(
                //                         vec![
                //                             ("status".to_string(), Type::Num),
                //                             ("content".to_string(), Type::Str),
                //                         ],
                //                         Box::new(Type::WebReturn),
                //                     ),
                //                 );
                //                 error_type.insert(
                //                     "page".to_string(),
                //                     Type::Function(
                //                         vec![
                //                             ("status".to_string(), Type::Num),
                //                             ("content".to_string(), Type::Str),
                //                         ],
                //                         Box::new(Type::WebReturn),
                //                     ),
                //                 );
                //                 web_type.insert(
                //                     "error".to_string(),
                //                     Type::Custom(Custype::Object(error_type)),
                //                 );
                //                 Custype::Object(web_type)
                //             })); // io.web() returns a web helper object
                //         } else {
                //             return Err(format!("io.web() expects no arguments, got {}", args.len(),));
                //         }
                //     } else if obj == "io" && prop == "read" {
                //         if args.len() == 1 {
                //             return Ok(Type::Str); // io.read() returns a string (async by default)
                //         } else {
                //             return Err(format!("io.read() expects 1 argument, got {}", args.len(),));
                //         }
                //     } else if obj == "io" && prop == "write" {
                //         if args.len() == 2 {
                //             return Ok(Type::Num); // io.write() returns a number (async by default)
                //         } else {
                //             return Err(format!(
                //                 "io.write() expects 2 arguments, got {}",
                //                 args.len(),
                //             ));
                //         }
                //     } else if obj == "web" && (prop == "page" || prop == "text" || prop == "file") {
                //         if args.len() == 1 {
                //             return Ok(Type::WebReturn); // web.page() returns a response object
                //         } else {
                //             return Err(format!(
                //                 "web.{prop}() expects 1 argument, got {}",
                //                 args.len(),
                //             ));
                //         }
                //     } else if obj == "web" && prop == "redirect" {
                //         if args.len() == 2 {
                //             return Ok(Type::WebReturn); // web.redirect() returns a response object
                //         } else {
                //             return Err(format!(
                //                 "web.redirect() expects 2 arguments, got {}",
                //                 args.len(),
                //             ));
                //         }
                //     }
                // }
                // }

                // Existing function call type-checking
                let callee_type = infer_expr(callee)?;
                if let Type::Function(params, ret_type) = callee_type {
                    if args.len() != params.len() {
                        return type_error(
                            format!(
                                "Expected {} argument(s) but received {}",
                                params.len(),
                                args.len(),
                            ),
                            Some("Match the function signature or adjust the call site."),
                        );
                    }
                    // Special-case: first insert decides Obj(K) inner type when currently unknown (Nil)
                    if let Expr::Get(obj, mname) = &**callee {
                        if mname == "insert" {
                            if let Ok(Type::Kv(inner)) = infer_expr(obj.as_ref()) {
                                if *inner == Type::Nil {
                                    // Ensure key is Str; allow any value type on first insert
                                    let key_ty = infer_expr(&args[0])?;
                                    if key_ty != Type::Str {
                                        return type_error(
                                            format!(
                                                "Map keys must be Str, but argument 1 is {:?}",
                                                key_ty
                                            ),
                                            Some("Convert the key to a string before calling insert."),
                                        );
                                    }
                                    // Skip strict check for value here; caller will solidify type.
                                    return Ok(*ret_type);
                                }
                            }
                        }
                    }
                    // verify each arg’s inferred type against the declared parameter type
                    for (i, (_, param_tstr)) in params.iter().enumerate() {
                        let arg_t = infer_expr(&args[i])?;
                        if matches!(param_tstr, Type::Function(_, _)) {
                            // Accept any function value
                            if let Type::Function(_, _) = arg_t {
                                // OK
                            } else {
                                return type_error(
                                    format!(
                                        "Argument {} should be a function, but it has type {:?}",
                                        i + 1,
                                        arg_t,
                                    ),
                                    Some("Pass a lambda or named function that matches the expected callback signature."),
                                );
                            }
                        } else {
                            let expected = param_tstr;
                            if *expected != arg_t {
                                return type_error(
                                    format!(
                                        "Argument {} has type {:?}, but {:?} is required",
                                        i + 1,
                                        arg_t,
                                        expected,
                                    ),
                                    Some("Cast the argument or adjust the function signature so the types agree."),
                                );
                            }
                        }
                    }
                    Ok(*ret_type)
                } else {
                    type_error(
                        format!("Can only call functions, found value of type {:?}", callee_type),
                        Some("Make sure the expression before '()' evaluates to a function."),
                    )
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum MatchArm {
    CatchAll(String, Instruction),
    Literal(Expr, Instruction),
}

#[derive(Debug, Clone)]
enum Instruction {
    Let {
        name: String,
        value: Expr,
        type_hint: Type,
        global: bool,
    },
    Assign(Expr, Expr, Option<Type>),
    Println(Expr),
    Return(Expr),
    Break,
    Expr(Expr),
    If {
        condition: Expr,
        then: Vec<Instruction>,
        elses: Option<Box<Instruction>>,
    },
    Match {
        expr: Expr,
        arms: Vec<MatchArm>,
    },
    While {
        condition: Expr,
        body: Vec<Instruction>,
    },
    For {
        iterator: String,
        range: Expr,
        body: Vec<Instruction>,
    },
    Block(Vec<Instruction>),
    FunctionDef {
        name: String,
        params: Vec<(String, Type)>,
        return_type: Type,
        body: Vec<Instruction>,
    },
    CallFn {
        dest: Option<String>,
        name: String,
        args: Vec<Expr>,
    },
    Maybe(Expr, Box<Instruction>, Option<Box<Instruction>>),
    Use {
        module_name: String,
        mod_path: String,
    },
    Nothing,
}

#[derive(Clone)]
enum Value {
    Num(f64),
    Str(String),
    /// Special return value used to signal early exit from functions
    Bool(bool),
    Nil,
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Num(n) => write!(f, "Num({n})"),
            Self::Str(s) => write!(f, "Str({s})"),
            Self::Bool(b) => write!(f, "Bool({b})"),

            Self::Nil => write!(f, "nil"),
        }
    }
}

#[derive(Clone, Debug)]
struct ModuleFunction {
    name: String,
    params: Vec<(String, Type)>,
    return_type: Type,
    body: Vec<Instruction>,
}

#[derive(Clone, Debug)]
struct ModuleInfo {
    // functions and constants exported by the module
    functions: HashMap<String, ModuleFunction>,
    constants: HashMap<String, Expr>,
    // type map for fields (functions -> Function types, constants -> concrete types)
    field_types: HashMap<String, Type>,
    // Object/enum type definitions declared inside the module
    types: HashMap<String, Custype>,
}

impl Default for ModuleInfo {
    fn default() -> Self {
        Self {
            functions: HashMap::new(),
            constants: HashMap::new(),
            field_types: HashMap::new(),
            types: HashMap::new(),
        }
    }
}

#[derive(Default, Clone)]
struct PreCtx {
    var_types: HashMap<String, Type>,
    types: HashMap<String, Custype>,
    // Loaded modules and their exports (types only; no execution)
    modules: HashMap<String, ModuleInfo>,
    current_line: Cell<Option<usize>>,
}

impl PreCtx {
    fn current_line(&self) -> Option<usize> {
        self.current_line.get()
    }

    fn with_line<R, F>(&self, line: Option<usize>, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let prev = self.current_line.replace(line);
        let result = f();
        self.current_line.set(prev);
        result
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Custype {
    Object(HashMap<String, Type>),
    Enum(Vec<String>),
}

impl Default for Custype {
    fn default() -> Self {
        Custype::Enum(vec![])
    }
}

struct Parser {
    tokens: Vec<Token>,
    current: usize, // index into `tokens`
    pctx: PreCtx,
    current_return_type: Option<Type>,
    inside_maybe: Option<String>,
    saw_non_nil_return: bool,
    saw_nil_return: bool,
    is_global: bool,
    loop_depth: usize,
}

#[derive(Debug, Clone)]
enum Type {
    Num,
    Str,
    Bool,
    Nil,
    Io,
    WebReturn,
    RangeBuilder,
    Kv(Box<Type>),
    List(Box<Type>),
    Option(Box<Type>),
    Custom(Custype),
    Function(Vec<(String, Type)>, Box<Type>),
}

impl Type {
    fn unwrap(&self) -> Self {
        if let Self::Option(l) = self {
            l.unwrap()
        } else {
            self.clone()
        }
    }
    fn infer(&self, expected: &Type) -> Option<Type> {
        match (self, expected) {
            (Type::List(b), Type::List(e)) if **b == Type::Nil => Some(Type::List(e.clone())),
            (Type::Kv(b), Type::List(e)) if **b == Type::Nil => Some(Type::Kv(e.clone())),
            (o, e) => {
                if o == e {
                    Some(e.clone())
                } else {
                    None
                }
            }
        }
    }
}

fn merge_return_types(old: &Type, new: &Type) -> Option<Type> {
    if old == new {
        return Some(old.clone());
    }

    match (old, new) {
        (Type::Nil, other) => Some(Type::Option(Box::new(other.clone()))),
        (other, Type::Nil) => Some(Type::Option(Box::new(other.clone()))),
        (Type::Option(inner_old), Type::Option(inner_new)) => {
            merge_return_types(inner_old, inner_new).map(|merged| Type::Option(Box::new(merged)))
        }
        (Type::Option(inner_old), other) => {
            merge_return_types(inner_old, other).map(|merged| Type::Option(Box::new(merged)))
        }
        (other, Type::Option(inner_new)) => {
            merge_return_types(other, inner_new).map(|merged| Type::Option(Box::new(merged)))
        }
        _ => {
            if let Some(inferred) = old.infer(new) {
                Some(inferred)
            } else if let Some(inferred) = new.infer(old) {
                Some(inferred)
            } else {
                None
            }
        }
    }
}

impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Type::Num, Type::Num)
            | (Type::Str, Type::Str)
            | (Type::Bool, Type::Bool)
            | (Type::Nil, Type::Nil)
            | (Type::Io, Type::Io)
            | (Type::WebReturn, Type::WebReturn) => true,

            (Type::List(left), Type::List(right)) | (Type::Option(left), Type::Option(right)) => {
                left == right
            }

            (Type::Function(params_l, ret_l), Type::Function(params_r, ret_r)) => {
                params_l == params_r && ret_l == ret_r
            }

            (Type::Custom(map_l), Type::Custom(map_r)) => {
                map_l == map_r
                // Compare as maps: same length and all corresponding entries equal
                // if map_l.len() != map_r.len() {
                //     return false;
                // }
                // for (key, val_l) in map_l.iter() {
                //     match map_r.get(key) {
                //         Some(val_r) if *val_l == *val_r => continue,
                //         _ => return false,
                //     }
                // }
                // true
            }

            _ => false,
        }
    }
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            current: 0,
            pctx: PreCtx::default(),
            current_return_type: None,
            inside_maybe: None,
            saw_non_nil_return: false,
            saw_nil_return: false,
            is_global: true,
            loop_depth: 0,
        }
    }

    // ───── entry point ─────

    fn parse_program(&mut self) -> Result<Vec<Instruction>, String> {
        let mut prgm = Vec::new();
        self.pctx.var_types.insert("io".to_string(), Type::Io);

        // Add built-in Request object type
        let mut request_fields = HashMap::new();
        request_fields.insert("method".to_string(), Type::Str);
        request_fields.insert("path".to_string(), Type::Str);
        // Represent query and headers as strings (parsed, human-readable)
        request_fields.insert("query".to_string(), Type::Str);
        request_fields.insert("headers".to_string(), Type::Str);
        request_fields.insert("body".to_string(), Type::Option(Box::new(Type::Str)));
        self.pctx
            .types
            .insert("Request".to_string(), Custype::Object(request_fields));

        while !self.is_at_end() {
            prgm.push(self.parse_statement()?);
        }
        Ok(prgm)
    }

    fn parse_statement(&mut self) -> Result<Instruction, String> {
        while self.match_kind(TokenKind::Semicolon){}
        // Handle return statements with type inference and consistency checking
        if self.match_kind(TokenKind::Return) {
            let expr = self.expression()?;
            let expr_line = self.previous().line;
            let line_hint = self.previous().line;
            let ret_type = self
                .pctx
                .with_line(Some(line_hint), || expr.get_type(&self.pctx))?;
            // Track explicit nil/non-xnil returns for this function
            if ret_type == Type::Nil {
                self.saw_nil_return = true;
            } else {
                self.saw_non_nil_return = true;
            }
            // Unify return types: allow Nil and uniform type => Option(inner)
            let merged_return_type = if let Some(old) = self.current_return_type.clone() {
                merge_return_types(&old, &ret_type).ok_or_else(|| {
                    format!("Mismatched return types in function: {old:?} vs {ret_type:?}")
                })?
            } else {
                ret_type.clone()
            };
            self.current_return_type = Some(merged_return_type);
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Return(expr))
        } else if self.match_kind(TokenKind::Break) {
            if self.loop_depth == 0 {
                return Err("'break' can only be used inside a loop".into());
            }
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Break)
        } else if self.match_kind(TokenKind::For) {
            let iterator = if let TokenKind::Identifier(name) = self.peek().kind.clone() {
                self.advance();
                name
            } else {
                return Err(format!(
                    "Expected a loop variable after 'for', found {}",
                    self.peek().kind
                ));
            };

            self.consume(
                TokenKind::In,
                "Expected keyword 'in' in for loop declaration",
            )?;

            let range_expr = self.expression()?;
            let range_line = self.previous().line;
            let range_type = self
                .pctx
                .with_line(Some(range_line), || range_expr.get_type(&self.pctx))?;
            match range_type {
                Type::RangeBuilder => {}
                Type::List(_) => {
                    return Err("For loops iterate over io.range(...) builders".to_string());
                }
                other => {
                    return Err(format!(
                        "Incorrect type in for loop range expression: expected io.range(...), found {other:?}"
                    ));
                }
            }

            // Loop variable is numeric; register for type checking before parsing body
            self.pctx.var_types.insert(iterator.clone(), Type::Num);

            self.loop_depth += 1;
            let body_stmt = match self.parse_statement() {
                Ok(body) => {
                    self.loop_depth -= 1;
                    body
                }
                Err(e) => {
                    self.loop_depth -= 1;
                    return Err(e);
                }
            };

            Ok(Instruction::For {
                iterator,
                range: range_expr,
                body: vec![body_stmt],
            })
        } else if self.match_kind(TokenKind::Use) {
            let TokenKind::Identifier(modname) = self.peek().kind else {
                return Err("Expected module name after 'use'".to_string());
            };
            self.advance();
            self.consume(TokenKind::Colon, "Expected ':' after 'use'")?;

            let TokenKind::Str(modfile) = self.peek().kind else {
                return Err("Expected module file after ':' in use statement".to_string());
            };
            // Load and parse the module file, but DO NOT execute it.
            let module_src_path = format!("./deps/{modfile}/lib.qx");
            let module_src = match std::fs::read_to_string(&module_src_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error importing module {modfile}: {e}");
                    std::process::exit(70);
                }
            };

            // Tokenize and parse the module in isolation
            let mod_tokens = tokenize(module_src.chars().collect());
            if mod_tokens
                .iter()
                .any(|t| matches!(t.kind, TokenKind::Error(_, _)))
            {
                for t in mod_tokens {
                    if let TokenKind::Error(_, _) = t.kind {
                        t.print();
                    }
                }
                return Err(format!("Failed to tokenize module: {modfile}"));
            }

            let mut mod_parser = Parser::new(mod_tokens);
            let parsed = mod_parser
                .parse_program()
                .map_err(|e| format!("Failed to parse module {modfile}: {e}"))?;

            // Build an export surface: only functions and constant variables.
            let mut minfo = ModuleInfo::default();

            for instr in parsed {
                match instr {
                    Instruction::FunctionDef {
                        name,
                        params,
                        return_type,
                        body,
                    } => {
                        // Record function signature in field types
                        minfo.field_types.insert(
                            name.clone(),
                            Type::Function(params.clone(), Box::new(return_type.clone())),
                        );
                        // Save full function for codegen; DO NOT execute
                        minfo.functions.insert(
                            name.clone(),
                            ModuleFunction {
                                name,
                                params,
                                return_type,
                                body,
                            },
                        );
                    }
                    Instruction::Let {
                        name,
                        value,
                        type_hint,
                        global,
                    } => {
                        // Only allow literal constants to avoid executing code
                        let is_literal = matches!(
                            value,
                            Expr::Literal(Value::Num(_))
                                | Expr::Literal(Value::Str(_))
                                | Expr::Literal(Value::Bool(_))
                                | Expr::Literal(Value::Nil)
                        );
                        if !is_literal {
                            // Skip non-literal variables; they would require execution to evaluate
                            continue;
                        }
                        // Determine type: prefer explicit type hint, else infer using module parser's context
                        let vtype = if type_hint != Type::Nil {
                            type_hint
                        } else {
                            mod_parser
                                .pctx
                                .with_line(None, || value.get_type(&mod_parser.pctx))
                                .unwrap_or(Type::Nil)
                        };
                        minfo.field_types.insert(name.clone(), vtype);
                        minfo.constants.insert(name, value);
                    }
                    _ => {
                        // Ignore any other statements in modules
                    }
                }
            }

            minfo.types = mod_parser.pctx.types.clone();

            // Prevent name collisions with existing variables/types
            if self.pctx.var_types.contains_key(&modname) || self.pctx.types.contains_key(&modname)
            {
                return Err(format!(
                    "Name '{}' already in use; cannot import module with this name",
                    modname
                ));
            }

            // Expose the module as a typed object on the global context for type checking
            self.pctx.modules.insert(modname.clone(), minfo.clone());
            self.pctx.var_types.insert(
                modname.clone(),
                Type::Custom(Custype::Object(minfo.field_types.clone())),
            );

            Ok(Instruction::Use {
                module_name: modname,
                mod_path: modfile,
            })
        } else if self.match_kind(TokenKind::Maybe) {
            let prev_inside = &self.inside_maybe.clone();
            let maybe = self.expression()?;
            self.inside_maybe = if let Expr::Variable(ref v) = maybe {
                Some(v.clone())
            } else {
                None
            };
            match self.inside_maybe.as_ref() {

                Some(var_name) => {            let old_type = { self.pctx.var_types.get(var_name).unwrap() };
            self.pctx.var_types.insert(
                var_name.to_string(),
                match old_type {
                    Type::Option(o) => *o.clone(),
                    _ => old_type.clone(),
                },
            );} None => {}
            }


            let block = self.parse_statement()?;
            let mut once_else = None;
            if self.match_kind(TokenKind::Else) {
                once_else = Some(Box::new(self.parse_statement()?));
            }

            self.inside_maybe = prev_inside.clone();

            Ok(Instruction::Maybe(maybe, Box::new(block), once_else))
        } else if self.match_kind(TokenKind::LBrace) {
            let was = self.is_global;
            self.is_global = false;
            // Static type scope for block: save outer types
            let saved_types = self.pctx.var_types.clone();
            let mut stmts = Vec::new();
            while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
                stmts.push(self.parse_statement()?);
            }
            self.consume(TokenKind::RBrace, "Expected '}' after block")?;
            // Restore outer static types after block
            self.pctx.var_types = saved_types;
            self.is_global = was;
            Ok(Instruction::Block(stmts))
        } else if self.match_kind(TokenKind::Print) || self.match_kind(TokenKind::Reprint) {
            let prkind = self.previous().clone();
            let expr = self.expression()?;
            // Static type checking for print expression
            let print_line = self.previous().line;
            let _expr_type = self
                .pctx
                .with_line(Some(print_line), || expr.get_type(&self.pctx))?;

            if let Some(var_name) = &self.inside_maybe {
                match _expr_type {
                    Type::Nil | Type::Option(_) => {
                        if let Expr::Variable(ref vname) = expr {
                            if vname != var_name {
                                return Err(
                            "Cannot use a value that might be none outside of a `maybe` block."
                                .into(),
                        );
                            }
                        }
                    }
                    _ => {}
                }
            }
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Println(expr))
        } else if self.match_kind(TokenKind::Object) {
            let Identifier(obj_name) = self.peek().kind else {
                return Err(format!(
                    "Expected Identifier after object, found {}",
                    self.peek().kind
                ));
            };
            self.advance();
            self.consume(LBrace, "Expected a { after object name")?;
            let mut fields = HashMap::new();
            while !self.match_kind(TokenKind::RBrace) {
                let Identifier(field) = self.peek().kind else {
                    return Err(format!(
                        "[line {}] Expected identifier, found {}",
                        self.peek().line,
                        self.peek().kind
                    ));
                };
                self.advance();
                self.consume(
                    Colon,
                    format!(
                        "Expected : after field name, found {} and {}",
                        self.previous().value,
                        self.peek().value
                    )
                    .as_str(),
                )?;
                let act_typ = self.parse_type()?;

                fields.insert(field, act_typ);

                if self.match_kind(TokenKind::Comma) {
                    continue;
                }

                if self.check(&TokenKind::RBrace) {
                    continue;
                }

                return Err(format!(
                    "Expected comma after field type, found {}",
                    self.peek().kind
                ));
            }

            self.pctx.types.insert(obj_name, Custype::Object(fields));

            Ok(Instruction::Nothing)
        } else if self.match_kind(TokenKind::Enum) {
            let TokenKind::Identifier(ename) = self.peek().kind else {
                return Err(format!(
                    "Expected identifier for enum name, found {}",
                    self.peek().kind
                ));
            };
            self.advance();
            self.consume(TokenKind::LBrace, "Expected '{' after enum name")?;
            let mut variants = vec![];
            while !self.match_kind(TokenKind::RBrace) {
                let TokenKind::Identifier(variant_name) = self.peek().kind else {
                    return Err(format!(
                        "Expected identifier for enum variant, found {}",
                        self.peek().kind
                    ));
                };
                self.advance();
                self.consume(
                    TokenKind::Comma,
                    format!(
                        "Expected Comma after enum variant, found {}",
                        self.peek().value
                    )
                    .as_str(),
                )?;
                variants.push(variant_name);
            }
            self.pctx.types.insert(ename, Custype::Enum(variants));
            Ok(Instruction::Nothing)
        } else if self.match_kind(TokenKind::Fun) {
            if self.is_at_end() {
                return Err(format!(
                    "[line {}] Unexpected keyword: fun",
                    self.previous().line
                ));
            }
            let Identifier(fun_name) = self.peek().kind else {
                return Err(format!(
                    "[line {}] Expected function name after fun, got {}",
                    self.peek().line,
                    self.peek().value
                ));
            };
            self.advance();
            self.consume(LParen, "Expected '(' after function name")?;

            let (params, fn_ret_type, block) = self.parse_fn_params_body()?;

            // Store the function's type signature for strong typing on calls
            self.pctx.var_types.insert(
                fun_name.clone(),
                Type::Function(params.clone(), Box::new(fn_ret_type.clone())),
            );
            Ok(Instruction::FunctionDef {
                body: vec![block],
                name: fun_name,
                params,
                return_type: fn_ret_type,
            })
        } else if self.match_kind(TokenKind::If) {
            // Parse the primary `if`
            let condition = self.expression()?;
            let condition_line = self.previous().line;
            let then_block_stmt = self.parse_statement()?;
            // Build an else-chain for any number of else-if or else clauses
            let mut else_node: Option<Box<Instruction>> = None;
            // A mutable pointer to the current nested else slot
            let mut current_else = &mut else_node;
            // Keep consuming `else` clauses
            while self.match_kind(TokenKind::Else) {
                if self.match_kind(TokenKind::If) {
                    // else-if clause
                    let else_condition = self.expression()?;
                    let else_stmt = self.parse_statement()?;
                    // Create a new nested If node
                    let new_if = Instruction::If {
                        condition: else_condition,
                        then: vec![else_stmt],
                        elses: None,
                    };
                    // Insert it into the current slot
                    *current_else = Some(Box::new(new_if));
                    // Descend into its `elses` field for further chaining
                    {
                        // Descend into the nested `If` instruction's `elses` field
                        let boxed_if = current_else.as_mut().unwrap();
                        if let Instruction::If { ref mut elses, .. } = **boxed_if {
                            current_else = elses;
                        } else {
                            unreachable!("Chained else must be an Instruction::If");
                        }
                    }
                } else {
                    // plain else: treat as an If with a true condition
                    let else_stmt = self.parse_statement()?;
                    let new_if = Instruction::If {
                        condition: Expr::Literal(Value::Bool(true)),
                        then: vec![else_stmt],
                        elses: None,
                    };
                    *current_else = Some(Box::new(new_if));
                    break; // no more chaining after a plain else
                }
            }
            if self
                .pctx
                .with_line(Some(condition_line), || condition.get_type(&self.pctx))?
                != Type::Bool
            {
                return Err("If conditions must be booleans".to_string());
            }
            Ok(Instruction::If {
                condition,
                then: vec![then_block_stmt],
                elses: else_node,
            })
        } else if self.match_kind(TokenKind::Match) {
            let matching_expr = self.expression()?;
            let matching_line = self.previous().line;
            let matching_expr_type = self
                .pctx
                .with_line(Some(matching_line), || matching_expr.get_type(&self.pctx))?;
            self.consume(
                TokenKind::LBrace,
                &format!("Expected '{{' after match, found {}", self.peek().kind),
            )?;
            let mut arms: Vec<MatchArm> = vec![];
            while !self.match_kind(TokenKind::RBrace) {
                let matching = self.expression()?;
                let case_line = self.previous().line;
                if let Expr::Variable(ref name) = matching {
                    self.consume(
                        TokenKind::BigArrow,
                        &format!("Expected => in match statement, found {}", self.peek().kind),
                    )?;
                    let previous = self
                        .pctx
                        .var_types
                        .insert(name.to_string(), matching_expr_type.clone());

                    let runs = self.parse_statement()?;
                    if let Some(prev) = previous {
                        self.pctx.var_types.insert(name.to_string(), prev);
                    } else {
                        self.pctx.var_types.remove(name);
                    }
                    arms.push(MatchArm::CatchAll(name.to_string(), runs));
                    self.match_kind(TokenKind::Comma);
                } else if self
                    .pctx
                    .with_line(Some(case_line), || matching.get_type(&self.pctx))?
                    .infer(&matching_expr_type)
                    .is_none()
                {
                    eprintln!(
                        "Matching wrong type, expr is type {:?}",
                        matching_expr_type
                    );
                    std::process::exit(70);
                } else {
                    self.consume(
                        TokenKind::BigArrow,
                        &format!("Expected => in match statement, found {}", self.peek().kind),
                    )?;
                    let runs = self.parse_statement()?;
                    arms.push(MatchArm::Literal(matching, runs));
                    self.match_kind(TokenKind::Comma);
                }
            }

            Ok(Instruction::Match {
                expr: matching_expr,
                arms,
            })
        } else if self.match_kind(TokenKind::While) {
            // Parse while loop condition
            let expr = self.expression()?;
            let cond_line = self.previous().line;
            // Static type checking: ensure condition is boolean
            let cond_type = self
                .pctx
                .with_line(Some(cond_line), || expr.get_type(&self.pctx))?;
            if cond_type != Type::Bool {
                return Err(format!(
                    "Condition in 'while' statement must be a boolean, found {:?}",
                    cond_type,
                ));
            }
            // Parse the loop body (a statement, e.g., a block)
            self.loop_depth += 1;
            let body = match self.parse_statement() {
                Ok(stmt) => {
                    self.loop_depth -= 1;
                    stmt
                }
                Err(e) => {
                    self.loop_depth -= 1;
                    return Err(e);
                }
            };
            // Generate a function for the while loop
            Ok(Instruction::While {
                body: vec![body],
                condition: expr,
            })
        } else if self.match_kind(TokenKind::Let) {
            let (expr_line,var_name) = if let TokenKind::Identifier(n) = self.peek().kind.clone() {
                (self.advance().line, n)
            } else {
                return Err("Expected a variable name after 'let'".into());
            };
            let mut type_hint = None;
            if self.match_kind(Colon) {
                type_hint = Some(self.parse_type()?);
            }
            self.consume(TokenKind::Equal, "Expected = after variable name")?;
            let expr = self.expression()?;
            // Special-case list literal assignment
            if let Expr::List(items) = expr.clone() {
                self.consume(
                    TokenKind::Semicolon,
                    "Expected ';' after variable declaration",
                )?;
                let name = var_name.clone();
                // Register the inferred list type for static checking
                let inner_type = if let Some(first) = items.first() {
                    self
                        .pctx
                        .with_line(Some(expr_line), || first.get_type(&self.pctx))?
                } else {
                    Type::Nil
                };
                self.pctx
                    .var_types
                    .insert(name.clone(), Type::List(Box::new(inner_type)));
            }
            // Static type checking: infer expression type and enforce consistency
            let expr_type = self
                .pctx
                .with_line(Some(expr_line), || expr.get_type(&self.pctx))?;
            let real_type = if let Some(hint) = type_hint {
                match (expr_type.clone(), (hint)) {
                    (Type::Kv(l), Type::Kv(y)) => Type::Kv(y),
                    (Type::List(act), Type::List(exp)) if *act == Type::Nil => Type::List(exp),
                    (act, exp) => {
                        if act != exp {
                            eprintln!(
                                "Expected type {exp:?}, found {act:?} for variable {var_name}"
                            );
                            std::process::exit(70);
                        } else {
                            exp
                        }
                    }
                }
            } else {
                expr_type.clone()
            };
            if let Some(existing) = self.pctx.var_types.get(&var_name) {
                let redeclaration_conflict = if *existing == real_type {
                    false
                } else {
                    match (existing, &real_type) {
                        (Type::List(inner), Type::List(_)) if **inner == Type::Nil => false,
                        (Type::Kv(inner), Type::Kv(_)) if **inner == Type::Nil => false,
                        _ => true,
                    }
                };

                if redeclaration_conflict {
                    return Err(format!(
                        "Cannot redeclare variable '{var_name}' with different type. Previous: {existing:?}, New: {real_type:?}",
                    ));
                }
            }
            self.pctx
                .var_types
                .insert(var_name.clone(), real_type.clone());
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Let {
                name: var_name,
                value: expr,
                type_hint: real_type,
                global: self.is_global,
            })
        } else {
            // expression statement or assignment with complex left-hand side
            let expr: Expr = self.expression()?;
            let lhs_line = self.previous().line;

            if self.match_kind(TokenKind::Equal) {
                if !valid_left_hand(&expr) {
                    return Err("Invalid assignment target".to_string());
                }
                let value_expr = self.expression()?;
                let value_line = self.previous().line;
                let value_type = self
                    .pctx
                    .with_line(Some(value_line), || value_expr.get_type(&self.pctx))?;

                // Perform type enforcement based on left-hand side kind
                let types_compatible = |expected: &Type, value: &Type| -> bool {
                    if expected == value {
                        true
                    } else if let Type::Option(inner) = expected {
                        **inner == value.clone() || matches!(value, Type::Nil)
                    } else {
                        false
                    }
                };

                match &expr {
                    Expr::Variable(name) => {
                        if let Some(existing) = self.pctx.var_types.get(name) {
                            if !types_compatible(existing, &value_type) && *existing != Type::Nil {
                                return Err(format!(
                                    "Cannot assign to variable '{}' with different type. Previous: {:?}, New: {:?}",
                                    name, existing, value_type,
                                ));
                            }
                        } else {
                            return Err(format!("Variable '{}' used before declaration", name));
                        }
                        if let Some(existing) = self.pctx.var_types.get(name) {
                            if *existing == Type::Nil {
                                self.pctx.var_types.insert(name.clone(), value_type.clone());
                            }
                        }
                    }
                    _ => {
                        let target_type = self
                            .pctx
                            .with_line(Some(lhs_line), || expr.get_type(&self.pctx))?;
                        if !types_compatible(&target_type, &value_type) {
                            return Err(format!(
                                "Assignment type mismatch: expected {:?}, got {:?}",
                                target_type, value_type
                            ));
                        }
                    }
                }

                self.match_kind(TokenKind::Semicolon);
                return Ok(Instruction::Assign(expr, value_expr, Some(value_type)));
            }

            let expr_type = self
                .pctx
                .with_line(Some(lhs_line), || expr.get_type(&self.pctx))?;
            if self.inside_maybe.is_none() {
                if let Type::Option(_) = expr_type {
                    return Err(
                        "Cannot use a value that might be none outside of a `maybe` block.".into(),
                    );
                }
            }
            // If this is a first insert into an Obj (Kv(Nil)), adopt the inserted value's type
            if let Expr::Call(callee, args) = &expr {
                if let Expr::Get(obj, method) = &**callee {
                    if method == "insert" && args.len() == 2 {
                        if let Expr::Variable(var_name) = &**obj {
                            if let Some(Type::Kv(inner)) =
                                self.pctx.var_types.get(var_name).cloned()
                            {
                                if *inner == Type::Nil {
                                    let val_ty = self
                                        .pctx
                                        .with_line(Some(lhs_line), || args[1].get_type(&self.pctx))?;
                                    self.pctx
                                        .var_types
                                        .insert(var_name.clone(), Type::Kv(Box::new(val_ty)));
                                }
                            }
                        }
                    }
                }
            }
            Ok(Instruction::Expr(expr))
        }
    }

    fn parse_type(&mut self) -> Result<Type, String> {
        match self.peek().kind {
            Maybe => {
                self.advance();
                let inner = self.parse_type()?;
                Ok(Type::Option(Box::new(inner)))
            }
            LBrack => {
                self.advance();
                let inside = self.parse_type()?;

                self.consume(TokenKind::RBrack, "Expected ] after type for list type")?;
                Ok(Type::List(Box::new(inside)))
            }
            TokenKind::Identifier(ident) => {
                let st = match ident.as_str() {
                    "Str" => Some(Type::Str),
                    "Bool" => Some(Type::Bool),
                    "Num" => Some(Type::Num),
                    "Obj" => None,
                    l => {
                        if let Some(t) = self.pctx.types.get(l) {
                            Some(Type::Custom(t.clone()))
                        } else {
                            return Err(format!("Type {l} not found"));
                        }
                    }
                };
                self.advance();
                let mut typarams = vec![];

                if self.match_kind(TokenKind::LParen) {
                    while !self.match_kind(RParen) {
                        typarams.push(self.parse_type()?);
                    }
                }
                match st {
                    Some(r) => Ok(r),
                    None => match ident.as_str() {
                        "Obj" => Ok(Type::Kv(Box::new(typarams[0].clone()))),
                        _ => return Err(format!("Type parameters not required for {ident}")),
                    },
                }
            }
            _ => panic!(),
        }
    }

    // ───── recursive-descent grammar ─────
    fn expression(&mut self) -> Result<Expr, String> {
        self.or()
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut expr = self.and()?;

        while self.match_any(&[TokenKind::Or, TokenKind::PipePipe]) {
            let right = self.and()?;
            expr = Expr::Binary(Box::new(expr), BinOp::Or, Box::new(right));
        }

        Ok(expr)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut expr = self.equality()?;

        while self.match_any(&[TokenKind::And, TokenKind::AmpAmp]) {
            let right = self.equality()?;
            expr = Expr::Binary(Box::new(expr), BinOp::And, Box::new(right));
        }

        Ok(expr)
    }

    fn parse_fn_params_body(&mut self) -> Result<(Vec<(String, Type)>, Type, Instruction), String> {
        let mut params = vec![];
        while !self.is_at_end() && self.peek().kind != RParen {
            let param_name = if let Identifier(i) = self.peek().kind {
                i
            } else {
                return Err(format!(
                    "[line {}] Expected parameter name after '(', got {}",
                    self.peek().line,
                    self.peek().value
                ));
            };
            self.advance();
            self.consume(Colon, {
                if self.peek().kind == Comma {
                    return Err(format!(
                        "Function parameters must have types, try: {}: Str or {}: Num",
                        param_name, param_name,
                    ));
                } else {
                    "Expected ':' after param name"
                }
            })?;
            let Identifier(typ) = self.peek().kind else {
                return Err(format!(
                    "Expected tpe after ':', found {}",
                    self.peek().kind
                ));
            };
            // consume the type token so we don't re-enter the loop on it
            self.advance();
            if self.peek().kind == Comma {
                self.advance();
            }
            params.push((param_name, typ));
        }
        self.advance();

        // Insert parameter types into context for static type checking within function body
        let mut new_params = vec![];
        for (param_name, param_type_str) in &params {
            let param_type = match param_type_str.as_str() {
                "Num" => Type::Num,
                "Str" => Type::Str,
                "Bool" => Type::Bool,
                custom_type => {
                    // Check if it's a custom type (like Request)
                    if let Some(type_def) = self.pctx.types.get(custom_type) {
                        Type::Custom(type_def.clone())
                    } else {
                        Type::Nil
                    }
                }
            };
            new_params.push((param_name.clone(), param_type.clone()));
            self.pctx
                .var_types
                .insert(param_name.clone(), param_type.clone());
        }

        // Reset return type inference and flags for this new function
        self.current_return_type = None;
        self.saw_non_nil_return = false;
        self.saw_nil_return = false;

        let block = self.parse_statement()?;

        // Compute function return type:
        // - Mixed nil and non-nil ⇒ Option(inner)
        // - Only non-nil ⇒ inner
        // - No non-nil ⇒ Nil
        let fn_ret_type = if self.saw_non_nil_return && self.saw_nil_return {
            // Mixed returns: Option of inner non-nil type
            match self.current_return_type.clone() {
                Some(Type::Option(inner)) => Type::Option(inner),
                Some(inner) if inner != Type::Nil => Type::Option(Box::new(inner)),
                _ => Type::Nil,
            }
        } else if self.saw_non_nil_return {
            // Only non-nil returns: return that type
            match self.current_return_type.clone() {
                Some(inner) if inner != Type::Nil => inner,
                _ => Type::Nil,
            }
        } else {
            // No non-nil returns ⇒ always nil
            Type::Nil
        };
        Ok((new_params, fn_ret_type, block))
    }

    fn equality(&mut self) -> Result<Expr, String> {
        let mut expr = self.comparison()?;

        while self.match_any(&[TokenKind::BangEqual, TokenKind::EqualEqual]) {
            let op = match self.previous().clone().kind {
                BangEqual => BinOp::NotEq,
                EqualEqual => BinOp::EqEq,
                _ => unreachable!(),
            };
            let right = self.comparison()?;
            expr = Expr::Binary(Box::new(expr), op, Box::new(right));
        }
        Ok(expr)
    }

    fn comparison(&mut self) -> Result<Expr, String> {
        let mut expr = self.term()?;

        while self.match_any(&[
            TokenKind::Greater,
            TokenKind::GreaterEqual,
            TokenKind::Less,
            TokenKind::LessEqual,
        ]) {
            let op = match self.previous().clone().kind {
                Greater => BinOp::Greater,
                GreaterEqual => BinOp::GreaterEqual,
                Less => BinOp::Less,
                LessEqual => BinOp::LessEqual,
                _ => unreachable!(),
            };
            let right = self.term()?;
            expr = Expr::Binary(Box::new(expr), op, Box::new(right));
        }
        Ok(expr)
    }

    fn term(&mut self) -> Result<Expr, String> {
        let mut expr = self.factor()?;

        while self.match_any(&[TokenKind::Plus, TokenKind::Minus]) {
            let op = match self.previous().clone().kind {
                Plus => BinOp::Plus,
                Minus => BinOp::Minus,
                _ => unreachable!(),
            };
            let right = self.factor()?;
            expr = Expr::Binary(Box::new(expr), op, Box::new(right));
        }
        Ok(expr)
    }

    fn factor(&mut self) -> Result<Expr, String> {
        let mut expr = self.unary()?;

        while self.match_any(&[TokenKind::Star, TokenKind::Slash]) {
            let op = match self.previous().clone().kind {
                Star => BinOp::Mult,
                Slash => BinOp::Div,
                _ => unreachable!(),
            };
            let right = self.unary()?;
            expr = Expr::Binary(Box::new(expr), op, Box::new(right));
        }
        Ok(expr)
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.match_any(&[TokenKind::Bang, TokenKind::Minus]) {
            let op = match self.previous().clone().kind {
                Bang => Unary::Not,
                Minus => Unary::Neg,
                _ => unreachable!(),
            };
            let right = self.unary()?;
            return Ok(Expr::Unary(op, Box::new(right)));
        }
        // Parse any postfix chain (calls, indexing, property access)
        self.postfix()
    }

    // Parse a primary expression and then any number of postfix operators:
    // - property access: .ident
    // - indexing: [expr]
    // - calls: (args, ...)
    fn postfix(&mut self) -> Result<Expr, String> {
        let mut expr = self.primary()?;
        loop {
            if self.match_kind(TokenKind::Dot) {
                if let TokenKind::Identifier(name) = &self.peek().kind {
                    let prop = name.clone();
                    self.advance();
                    expr = Expr::Get(Box::new(expr), prop);
                } else {
                    return Err(format!(
                        "Expected identifier after '.', found {}",
                        self.peek().kind
                    ));
                }
            } else if self.match_kind(TokenKind::LBrack) {
                let index_pr = self.expression()?;
                self.consume(RBrack, "Expected ']' after list index")?;
                expr = Expr::Index(Box::new(expr), Box::new(index_pr));
            } else if self.match_kind(TokenKind::LParen) {
                let mut args = Vec::new();
                while !self.check(&TokenKind::RParen) {
                    args.push(self.expression()?);
                    if !self.match_kind(TokenKind::Comma) {
                        break;
                    }
                }
                self.consume(
                    TokenKind::RParen,
                    &format!(
                        "Expected ')' after arguments, found {}{}",
                        self.previous().kind,
                        self.peek().kind
                    ),
                )?;

                // If calling a direct variable function, keep existing type checks
                if let Expr::Variable(ref name) = expr {
                    if let Some(Type::Function(f, _)) = self.pctx.var_types.get(name).cloned() {
                        if f.len() != args.len() {
                            return Err(format!(
                                "Function parameters incorrect, expected {} found {}",
                                f.len(),
                                args.len(),
                            ));
                        }
                        for (i, arg) in args.iter().enumerate() {
                            let ty = self
                                .pctx
                                .with_line(None, || arg.get_type(&self.pctx))?;
                            let (_, te) = &f[i];
                            if *te != ty {
                                return Err(format!(
                                    "Function parameters incorrect, expected {te:?} found {ty:?}",
                                ));
                            }
                        }
                    }
                }
                expr = Expr::Call(Box::new(expr), args);
            } else {
                break;
            }
        }
        Ok(expr)
    }

    fn primary(&mut self) -> Result<Expr, String> {
        if self.match_kind(TokenKind::True) {
            return Ok(Expr::Literal(Value::Bool(true)));
        }
        if self.match_kind(TokenKind::False) {
            return Ok(Expr::Literal(Value::Bool(false)));
        }
        if self.match_kind(TokenKind::Nil) {
            return Ok(Expr::Literal(Value::Nil));
        }

        let pekd = self.peek().clone();

        if let TokenKind::Num(n) = pekd.kind {
            self.advance();
            let expr = Expr::Literal(Value::Num(n));
            return Ok(expr);
        } else if let TokenKind::Str(o) = &pekd.kind {
            self.advance();
            let expr = Expr::Literal(Value::Str(o.into()));
            return Ok(expr);
        } else if let TokenKind::Identifier(i) = &pekd.kind {
            self.advance();

            let is_object_type = matches!(self.pctx.types.get(i), Some(Custype::Object(_)));

            if is_object_type && self.check(&TokenKind::LBrace) {
                self.advance();
                let mut vals = HashMap::new();
                while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
                    let Identifier(key) = self.peek().kind else {
                        return Err(format!(
                            "Expected identifier, found {} and {}",
                            self.advance().value.clone(),
                            self.advance().value,
                        ));
                    };
                    self.advance();
                    self.consume(Colon, "Expected ':' after field name")?;
                    let expr = self.expression()?;
                    vals.insert(key, expr);

                    if self.match_kind(TokenKind::Comma) || self.check(&TokenKind::RBrace) {
                        continue;
                    }

                    self.consume(TokenKind::RBrace, "Expected '}' after object literal")?;
                    break;
                }
                if self.check(&TokenKind::RBrace) {
                    self.advance();
                }
                let Custype::Object(r) = self
                    .pctx
                    .types
                    .get(i)
                    .expect("Object type should exist for literal")
                else {
                    unreachable!();
                };
                let mut all_fields_present = true;
                for (name, typ) in r.iter() {
                    if let Some(r_val) = vals.get(name) {
                        let real_type = self
                            .pctx
                            .with_line(None, || r_val.get_type(&self.pctx))?;

                        if real_type.infer(typ).is_none() {
                            return Err(format!(
                                "Expected {name} to be type {typ:?}, got {real_type:?}",
                            ));
                        }
                    } else {
                        all_fields_present = false;
                        break;
                    }
                }
                if !all_fields_present {
                    return Err(format!("{i} object requires more fields"));
                }
                return Ok(Expr::Object(i.clone(), vals));
            }
            // start with a variable reference
            let expr = Expr::Variable(i.clone());

            // Continue in calling code (postfix) to allow chaining
            return Ok(expr);
        }

        if self.match_kind(TokenKind::LParen) {
            // parse grouped expression
            let expr = self.expression()?;
            self.consume(TokenKind::RParen, "Expect ')' after expression.")?;
            return Ok(expr);
        }

        if self.match_kind(TokenKind::LBrace) {
            let mut inner = Vec::new();
            while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
                inner.push(self.parse_statement()?);
            }
            self.consume(TokenKind::RBrace, "Expected '}' after block")?;
            return Ok(Expr::Block(inner));
        }

        if self.match_kind(TokenKind::LBrack) {
            let mut items = Vec::new();
            // handle empty list
            if self.check(&TokenKind::RBrack) {
                self.advance();
            } else {
                loop {
                    items.push(self.expression()?);
                    if self.match_kind(TokenKind::Comma) {
                        continue;
                    }
                    self.consume(TokenKind::RBrack, "Expected ']' after list")?;
                    break;
                }
            }
            let expr = Expr::List(items);
            return Ok(expr);
        }

        if self.match_kind(TokenKind::Fun) {
            self.consume(TokenKind::LParen, "Expected '(' after keyword fun")?;
            let (params, ret_type, body) = self.parse_fn_params_body()?;
            return Ok(Expr::Function(params, ret_type, Box::new(body)));
        }

        Err(format!(
            "[line {}] Error at '{}': Expect expression.",
            pekd.line, pekd.value
        ))
    }

    // ───── helpers ─────
    fn match_kind(&mut self, kind: TokenKind) -> bool {
        if self.check(&kind) {
            self.advance();
            true
        } else {
            false
        }
    }
    fn match_any(&mut self, kinds: &[TokenKind]) -> bool {
        for k in kinds {
            if self.check(k) {
                self.advance();
                return true;
            }
        }
        false
    }
    fn consume(&mut self, kind: TokenKind, msg: &str) -> Result<(), String> {
        if self.check(&kind) {
            self.advance();
            Ok(())
        } else {
            Err(msg.into())
        }
    }
    fn check(&self, kind: &TokenKind) -> bool {
        !self.is_at_end()
            && std::mem::discriminant(&self.peek().kind) == std::mem::discriminant(kind)
    }
    fn advance(&mut self) -> &Token {
        if !self.is_at_end() {
            self.current += 1;
        }
        self.previous()
    }
    fn is_at_end(&self) -> bool {
        matches!(self.peek().kind, TokenKind::Eof)
    }
    fn peek(&self) -> Token {
        if self.current < self.tokens.len() {
            self.tokens[self.current].clone()
        } else {
            Token {
                kind: Eof,
                value: "".into(),
                line: self.previous().line,
            }
        }
    }
    fn previous(&self) -> &Token {
        &self.tokens[self.current - 1]
    }
}

impl Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::LParen => "(".to_string(),
            Self::RParen => ")".to_string(),
            Self::LBrace => "{".to_string(),
            Self::RBrace => "}".to_string(),
            Self::LBrack => "[".to_string(),
            Self::RBrack => "]".to_string(),
            Self::Star => "*".to_string(),
            Self::Dot => ".".to_string(),
            Self::Comma => ",".to_string(),
            Self::Plus => "+".to_string(),
            Self::Minus => "-".to_string(),
            Self::AmpAmp => "&&".to_string(),
            Self::PipePipe => "||".to_string(),
            Self::Colon => ":".to_string(),
            Self::Semicolon => ";".to_string(),
            Self::Equal => "=".to_string(),
            Self::EqualEqual => "==".to_string(),
            Self::Bang => "!".to_string(),
            Self::BangEqual => "!=".to_string(),
            Self::Less => "<".to_string(),
            Self::LessEqual => "<=".to_string(),
            Self::Greater => ">".to_string(),
            Self::GreaterEqual => ">=".to_string(),
            Self::BigArrow => "=>".to_string(),
            Self::Slash => "/".to_string(),
            Self::Str(s) => {
                let binding = format!("\"{s}\"");
                binding
            }
            Self::Num(num) => format!("{num}"),
            Self::Identifier(ident) => ident.to_string(),
            Self::And => "and".to_string(),
            Self::Object => "object".to_string(),
            Self::Enum => "enum".to_string(),
            Self::Maybe => "maybe".to_string(),
            Self::Match => "match".to_string(),
            Self::Else => "else".to_string(),
            Self::False => "false".to_string(),
            Self::For => "for".to_string(),
            Self::Fun => "fun".to_string(),
            Self::If => "if".to_string(),
            Self::Nil => "none".to_string(),
            Self::Or => "or".to_string(),
            Self::Print => "print".to_string(),
            Self::Reprint => "reprint".to_string(),
            Self::Return => "return".to_string(),
            Self::Break => "break".to_string(),
            Self::Super => "super".to_string(),
            Self::This => "this".to_string(),
            Self::True => "true".to_string(),
            Self::Let => "let".to_string(),
            Self::In => "in".to_string(),
            Self::While => "while".to_string(),
            Self::Use => "use".to_string(),
            Self::Eof => "".to_string(),
            Self::Error(line, error) => format!("[line {line}] Error: {error}"),
        };
        write!(f, "{s}")
    }
}

fn is_single_char_token(c: char) -> Option<TokenKind> {
    match c {
        '(' => Some(LParen),
        ')' => Some(RParen),
        '{' => Some(LBrace),
        '}' => Some(RBrace),
        '*' => Some(Star),
        '.' => Some(Dot),
        ',' => Some(Comma),
        '+' => Some(Plus),
        '-' => Some(Minus),
        ':' => Some(Colon),
        ';' => Some(Semicolon),
        _ => None,
    }
}

fn get_special_ident(val: String) -> TokenKind {
    match val.as_str() {
        "and" => And,
        "object" => Object,
        "enum" => Enum,
        "maybe" => Maybe,
        "else" => Else,
        "false" => False,
        "for" => For,
        "in" => In,
        "fun" => Fun,
        "if" => If,
        "match" => Match,
        "none" => Nil,
        "nil" => Nil,
        "or" => Or,
        "print" => Print,
        "reprint" => Reprint,
        "return" => Return,
        "break" => Break,
        "super" => Super,
        "this" => This,
        "true" => True,
        "let" => Let,
        "while" => While,
        "use" => Use,
        _ => Identifier(val),
    }
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn returns_on_all_paths(block: Vec<Instruction>) -> bool {
    for inst in block {
        match inst {
            Instruction::Return(_) => return true,
            Instruction::Block(l) => {
                if returns_on_all_paths(l) {
                    return true;
                } else {
                    continue;
                }
            }

            Instruction::If {
                condition: _,
                then,
                elses,
            } => {
                let cert = returns_on_all_paths(then) && else_certifies(&elses); // recursive helper; never uses unwrap_or(Nothing)

                if cert {
                    return true;
                } else {
                    continue;
                }
            }
            Instruction::Match { expr:_, arms } => {
                let mut all_certified = true;
                for arm in arms {
                    let body = match arm {
                        MatchArm::CatchAll(_, b) => b,
                        MatchArm::Literal(_, a)=> a,
                    };
                    if !returns_on_all_paths(vec![body]) {
                        all_certified = false;
                        break;
                    }
 
                }
                if all_certified {
                    return true;
                }
            }
            Instruction::Maybe(_, body, elses) => {
                let cert = returns_on_all_paths(vec![*body]) && else_certifies(&elses); // recursive helper; never uses unwrap_or(Nothing)

                if cert {
                    return true;
                } else {
                    continue;
                }
            }
            _ => continue,
        }
    }
    false
}

fn valid_left_hand(left: &Expr) -> bool {
    match left {
        Expr::Get(ex, _) => valid_left_hand(ex),
        Expr::Variable(_) => true,
        Expr::Index(l, _) => valid_left_hand(l),
        _ => false,
    }
}

fn else_certifies(elses: &Option<Box<Instruction>>) -> bool {
    match elses {
        None => false, // no else branch => not guaranteed

        Some(b) => match &**b {
            Instruction::Block(inner) => {
                // final else { ... }
                returns_on_all_paths(inner.clone())
            }

            Instruction::If { then, elses, .. } => {
                if elses.is_none() {
                    returns_on_all_paths(then.clone()) 
                } else {
                    returns_on_all_paths(then.clone()) && else_certifies(elses)
                }
            }

            Instruction::Return(_) => {
                true
            }

            _ => false, 
        },
    }
}

#[derive(Clap, Debug)]
#[command(about, long_about = None, subcommand_required = false, arg_required_else_help = false)]
struct Args {
    /// Shows debugging info
    #[arg(short, long, default_value_t = false)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clap, Debug)]
enum Commands {
    Run { filename: Option<String> },
    Format { filename: Option<String> },
    #[command(external_subcommand)]
    Fallback(Vec<String>),
}

fn execute_run(filename: String, debug: bool) {
    let Ok(contents) = std::fs::read_to_string(&filename) else {
        eprintln!("Os error while reading file {filename}. Please try again later");
        std::process::exit(70);
    };
    let tokens = tokenize(contents.chars().collect());

    // Lexical error check
    if tokens.iter().any(|t| matches!(t.kind, Error(_, _))) {
        for t in tokens.iter() {
            t.print();
        }
        std::process::exit(65);
    }
    let mut parser = Parser::new(tokens);
    match parser.parse_program() {
        Ok(p) => {
            for ins in p.clone() {
                if let Instruction::FunctionDef {
                    name,
                    params: _,
                    return_type: _,
                    body,
                } = ins
                {
                    if !returns_on_all_paths(body) {
                        eprintln!(
                            "Body of function '{name}' does not return a value every time. Try adding `return none` at the end of the function"
                        );
                        std::process::exit(70);
                    }
                }
            }
            ensure_llvm_ready();
            let context = context::Context::create();
            let module = context.create_module("sum");
            let execution_engine = module
                .create_jit_execution_engine(OptimizationLevel::Aggressive)
                .unwrap();
            let initial_quick_types = parser.pctx.var_types.clone();
            let parser_ctx = parser.pctx;
            let codegen = Compiler {
                context: &context,
                module,
                builder: context.create_builder(),
                execution_engine,
                instructions: p,
                vars: RefCell::new(HashMap::new()),
                var_types: RefCell::new(HashMap::new()),
                quick_var_types: RefCell::new(initial_quick_types),
                pctx: RefCell::new(parser_ctx),
                current_module: RefCell::new(None),
                closure_envs: RefCell::new(HashMap::new()),
                current_function: RefCell::new(Vec::new()),
                loop_stack: RefCell::new(Vec::new()),
            };

            // seed the C PRNG so io.random() varies each run
            unsafe {
                // get current epoch seconds
                let now = time(ptr::null_mut());
                srand(now as u32);
            }
            let sum = codegen
                .run_code()
                .ok_or("Unable to JIT compile code")
                .unwrap();
            if debug {
                let _ = codegen.module.print_to_file("./ll.v");
            }

            unsafe {
                let res = sum.call();
                if res != 0.0 {
                    std::process::exit(res as i32);
                }
            }

            // If an HTTP server was started, keep the process alive.
            // Wait briefly for the server to transition to running if needed.
            let mut waited = 0u32;

            while !SERVER_RUNNING.load(Ordering::Relaxed) && waited < 1 {
                std::thread::sleep(Duration::from_millis(1));
                waited += 1;
            }
            if SERVER_RUNNING.load(Ordering::Relaxed) {
                // Park the main thread indefinitely. Ctrl+C will terminate the process.
                std::thread::park();
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(65);
        }
    }
}

fn main() {
    let args = Args::parse();
    let debug = args.debug;

    let command = args
        .command
        .unwrap_or(Commands::Run { filename: None });

    match command {
        Commands::Run { filename } => {
            let filename = filename.unwrap_or("./src/main.qx".to_string());
            execute_run(filename, debug);
        }
        Commands::Fallback(mut extra) => {
            let filename = if extra.is_empty() {
                "./src/main.qx".to_string()
            } else {
                let filename = extra.remove(0);
                if !extra.is_empty() {
                    eprintln!("Unexpected arguments: {}", extra.join(" "));
                    std::process::exit(64);
                }
                filename
            };
            execute_run(filename, debug);
        }
        Commands::Format { filename } => {
            let filename = filename.unwrap_or("./src/main.qx".to_string());
            let Ok(contents) = std::fs::read_to_string(&filename) else {
                eprintln!("Os error while reading file {filename}. Please try again later");
                std::process::exit(70);
            };
            let tokens = tokenize(contents.chars().collect());
            if tokens.iter().any(|t| matches!(t.kind, Error(_, _))) {
                for t in tokens {
                    if let Error(_, _) = t.kind {
                        t.print();
                    }
                }
                std::process::exit(65);
            }

            let mut formatted = String::new();
            let mut indent = 0usize;
            let mut line_open = false;
            let mut prev_kind: Option<TokenKind> = None;

            let mut push_indent = |buf: &mut String, indent: usize, line_open: &mut bool| {
                if !*line_open {
                    for _ in 0..indent {
                        buf.push('\t');
                    }
                    *line_open = true;
                }
            };

            let mut trim_trailing_space = |buf: &mut String| {
                while buf.ends_with(' ') {
                    buf.pop();
                }
            };

            let mut tokens = tokens.into_iter().peekable();
            while let Some(token) = tokens.next() {
                let kind = token.kind;
                match &kind {
                    LBrace => {
                        if matches!(
                            prev_kind,
                            Some(
                                Identifier(_)
                                    | RParen
                                    | RBrack
                                    | True
                                    | False
                                    | Nil
                                    | Return
                                    | Else
                            )
                        ) {
                            if !formatted.ends_with([' ', '\n', '\t']) {
                                formatted.push(' ');
                            }
                        }
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push('{');
                        formatted.push('\n');
                        line_open = false;
                        indent += 1;
                    }
                    RBrace => {
                        indent = indent.saturating_sub(1);
                        if !formatted.ends_with('\n') {
                            trim_trailing_space(&mut formatted);
                            formatted.push('\n');
                            line_open = false;
                        }
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push('}');
                        if matches!(tokens.peek().map(|t| &t.kind), Some(Else)) {
                            formatted.push(' ');
                            line_open = true;
                        } else {
                            formatted.push('\n');
                            line_open = false;
                        }
                    }
                    Semicolon => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push(';');
                        formatted.push('\n');
                        line_open = false;
                    }
                    Comma => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push(',');
                        formatted.push(' ');
                        line_open = true;
                    }
                    Dot => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push('.');
                    }
                    Colon => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push(':');
                        formatted.push(' ');
                        line_open = true;
                    }
                    LParen => {
                        if matches!(
                            prev_kind,
                            Some(
                                If | For
                                    | While
                                    | Maybe
                                    | Fun
                                    | Print
                                    | Reprint
                                    | Return
                                    | Let
                                    | Use
                            )
                        ) && !formatted.ends_with([' ', '\n', '\t', '('])
                        {
                            formatted.push(' ');
                        }
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push('(');
                    }
                    RParen => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push(')');
                    }
                    LBrack => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push('[');
                    }
                    RBrack => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push(']');
                    }
                    Str(inner) => {
                        push_indent(&mut formatted, indent, &mut line_open);
                        if !matches!(prev_kind, Some(LParen | Dot | LBrack | Colon))
                            && !formatted.ends_with([' ', '\n', '\t'])
                        {
                            formatted.push(' ');
                        }
                        formatted.push_str(&format!("\"{}\"", inner.replace("\"", "\\\"")));
                    }
                    Identifier(name) => {
                        push_indent(&mut formatted, indent, &mut line_open);
                        if !matches!(prev_kind, Some(LParen | Dot | LBrack | Colon | Fun))
                            && !formatted.ends_with([' ', '\n', '\t'])
                        {
                            formatted.push(' ');
                        }
                        formatted.push_str(name);
                    }
                    Num(num) => {
                        push_indent(&mut formatted, indent, &mut line_open);
                        if !matches!(prev_kind, Some(LParen | Dot | LBrack | Colon))
                            && !formatted.ends_with([' ', '\n', '\t'])
                        {
                            formatted.push(' ');
                        }
                        formatted.push_str(&format!("{num}"));
                    }
                    And | Or | Object | Enum | Maybe | Else | False | For | Fun | If | Match
                    | Nil | Print | Reprint | Return | Break | Super | This | True | Let
                    | While | Use | In => {
                        push_indent(&mut formatted, indent, &mut line_open);
                        if !matches!(prev_kind, Some(LParen | Dot | Colon))
                            && !formatted.ends_with([' ', '\n', '\t'])
                        {
                            formatted.push(' ');
                        }
                        formatted.push_str(match &kind {
                            And => "and",
                            Or => "or",
                            Object => "object",
                            Enum => "enum",
                            Maybe => "maybe",
                            Else => "else",
                            False => "false",
                            For => "for",
                            Fun => "fun",
                            If => "if",
                            Match => "match",
                            Nil => "none",
                            Print => "print",
                            Reprint => "reprint",
                            Return => "return",
                            Break => "break",
                            Super => "super",
                            This => "this",
                            True => "true",
                            Let => "let",
                            While => "while",
                            Use => "use",
                            In => "in",
                            _ => unreachable!(),
                        });
                    }
                    Plus | Minus | Star | Slash | EqualEqual | BangEqual | Less | LessEqual
                    | Greater | GreaterEqual | BigArrow | AmpAmp | PipePipe | Equal => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        if !formatted.ends_with([' ', '\n', '\t']) {
                            formatted.push(' ');
                        }
                        formatted.push_str(match &kind {
                            Plus => "+",
                            Minus => "-",
                            Star => "*",
                            Slash => "/",
                            EqualEqual => "==",
                            BangEqual => "!=",
                            Less => "<",
                            LessEqual => "<=",
                            Greater => ">",
                            GreaterEqual => ">=",
                            BigArrow => "=>",
                            AmpAmp => "&&",
                            PipePipe => "||",
                            Equal => "=",
                            _ => unreachable!(),
                        });
                        formatted.push(' ');
                    }
                    Bang => {
                        trim_trailing_space(&mut formatted);
                        push_indent(&mut formatted, indent, &mut line_open);
                        formatted.push('!');
                    }
                    Eof => {}
                    Error(_, _) => {}
                }
                prev_kind = Some(kind);
            }

            let mut final_output = formatted;
            trim_trailing_space(&mut final_output);
            if !final_output.ends_with('\n') {
                final_output.push('\n');
            }
            std::fs::write(filename, final_output).unwrap();
        }
    }
}

type SumFunc = unsafe extern "C" fn() -> f64;
struct Compiler<'ctx> {
    context: &'ctx context::Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    execution_engine: ExecutionEngine<'ctx>,
    instructions: Vec<Instruction>,
    vars: RefCell<HashMap<String, PointerValue<'ctx>>>,
    var_types: RefCell<HashMap<String, BasicTypeEnum<'ctx>>>,
    quick_var_types: RefCell<HashMap<String, Type>>,
    pctx: RefCell<PreCtx>,
    // Active module namespace during module function compilation
    current_module: RefCell<Option<String>>,
    // Captured environments for inline functions: closure name -> captured vars
    closure_envs: RefCell<HashMap<String, HashMap<String, CaptureDescriptor<'ctx>>>>,
    // Stack of function names currently being emitted
    current_function: RefCell<Vec<String>>,
    loop_stack: RefCell<Vec<LoopContext<'ctx>>>,
}
use inkwell::FloatPredicate;
use inkwell::IntPredicate;
use inkwell::types::BasicMetadataTypeEnum;
impl<'ctx> Compiler<'ctx> {
    fn get_active_capture_descriptor(&self, var_name: &str) -> Option<CaptureDescriptor<'ctx>> {
        let fn_name = {
            let stack = self.current_function.borrow();
            stack.last()?.clone()
        };
        self.closure_envs
            .borrow()
            .get(&fn_name)
            .and_then(|m| m.get(var_name))
            .cloned()
    }

    fn lookup_qtype(&self, var_name: &str) -> Option<Type> {
        if let Some(t) = self.quick_var_types.borrow().get(var_name) {
            return Some(t.clone());
        }
        self.pctx.borrow().var_types.get(var_name).cloned()
    }

    fn infer_expr_type(&self, expr: &Expr) -> Result<Type, String> {
        let mut ctx = self.pctx.borrow().clone();
        let quick_snapshot = self.quick_var_types.borrow().clone();
        for (name, ty) in quick_snapshot {
            ctx.var_types.insert(name, ty);
        }
        ctx.with_line(None, || expr.get_type(&ctx))
    }

    fn expr_type_matches<F>(&self, expr: &Expr, predicate: F) -> bool
    where
        F: Fn(Type) -> bool,
    {
        match self.infer_expr_type(expr) {
            Ok(t) => predicate(t),
            Err(_) => false,
        }
    }

    /// Expose C rand() → i32
    fn get_or_create_rand(&self) -> FunctionValue<'ctx> {
        self.module.get_function("rand").unwrap_or_else(|| {
            let fn_type = self.context.i32_type().fn_type(&[], false);
            self.module.add_function("rand", fn_type, None)
        })
    }

    fn qtype_to_llvm(&self, t: &Type) -> BasicTypeEnum<'ctx> {
        match t {
            Type::Num => self.context.f64_type().as_basic_type_enum(),
            Type::Bool => self.context.bool_type().as_basic_type_enum(),
            Type::Str
            | Type::Custom(_)
            | Type::WebReturn
            | Type::Io
            | Type::RangeBuilder
            | Type::Kv(_)
            | Type::List(_)
            | Type::Option(_) => self
                .context
                .ptr_type(AddressSpace::default())
                .as_basic_type_enum(),
            Type::Nil => self.context.f64_type().as_basic_type_enum(),
            Type::Function(_, _) => self
                .context
                .ptr_type(AddressSpace::default())
                .as_basic_type_enum(),
        }
    }

    fn declare_function(
        &self,
        name: &str,
        params: &[(String, Type)],
        return_type: &Type,
    ) -> FunctionValue<'ctx> {
        if let Some(existing) = self.module.get_function(name) {
            return existing;
        }

        let llvm_ret_type = self.qtype_to_llvm(return_type);
        let param_metadata_types: Vec<BasicMetadataTypeEnum> = params
            .iter()
            .map(|(_, ty)| self.qtype_to_llvm(ty).into())
            .collect();

        let fn_type = match llvm_ret_type {
            BasicTypeEnum::IntType(int_ty) => int_ty.fn_type(&param_metadata_types, false),
            BasicTypeEnum::PointerType(ptr_ty) => ptr_ty.fn_type(&param_metadata_types, false),
            BasicTypeEnum::FloatType(float_ty) => float_ty.fn_type(&param_metadata_types, false),
            BasicTypeEnum::ArrayType(array_ty) => array_ty.fn_type(&param_metadata_types, false),
            BasicTypeEnum::ScalableVectorType(vec_ty) => {
                vec_ty.fn_type(&param_metadata_types, false)
            }
            BasicTypeEnum::VectorType(vec_ty) => vec_ty.fn_type(&param_metadata_types, false),
            BasicTypeEnum::StructType(struct_ty) => struct_ty.fn_type(&param_metadata_types, false),
        };

        self.module.add_function(name, fn_type, None)
    }

    // Module functions are compiled in run_code by synthesizing namespaced
    // Instruction::FunctionDef entries and feeding them through compile_instruction.

    fn run_code(&self) -> Option<JitFunction<'_, SumFunc>> {
        let f64_type = self.context.f64_type();
        // Match SumFunc signature: three u64 parameters
        let fn_type = f64_type.fn_type(&[], false);
        let main_fn = self.module.add_function("main", fn_type, None);
        // Entry block and position builder
        let entry_bb = self.context.append_basic_block(main_fn, "entry");
        self.builder.position_at_end(entry_bb);
        let _main_scope = FunctionScopeGuard::new(&self.current_function, "main".to_string());
        // Compile module functions into the LLVM module first (no execution).
        {
            let modules: Vec<(String, ModuleInfo)> = self
                .pctx
                .borrow()
                .modules
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            for (modname, minfo) in &modules {
                for fdef in minfo.functions.values() {
                    let ns = format!("{}__{}", modname, fdef.name);
                    self.declare_function(&ns, &fdef.params, &fdef.return_type);
                }
            }

            for instr in &self.instructions {
                if let Instruction::FunctionDef {
                    name,
                    params,
                    return_type,
                    ..
                } = instr
                {
                    self.declare_function(name, params, return_type);
                }
            }

            for (modname, minfo) in modules {
                let saved_types = {
                    let pctx_ref = self.pctx.borrow();
                    pctx_ref.types.clone()
                };
                {
                    let mut pctx_mut = self.pctx.borrow_mut();
                    for (ty_name, custype) in &minfo.types {
                        pctx_mut
                            .types
                            .entry(ty_name.clone())
                            .or_insert(custype.clone());
                    }
                }

                for (_fname, fdef) in minfo.functions {
                    let instr = Instruction::FunctionDef {
                        name: format!("{}__{}", modname, fdef.name),
                        params: fdef.params.clone(),
                        return_type: fdef.return_type.clone(),
                        body: fdef.body.clone(),
                    };
                    *self.current_module.borrow_mut() = Some(modname.clone());
                    self.compile_instruction(main_fn, &instr).unwrap();
                    *self.current_module.borrow_mut() = None;
                }

                self.pctx.borrow_mut().types = saved_types;
            }
        }
        // 1) Compile all function definitions first
        for instr in &self.instructions {
            if let Instruction::FunctionDef { .. } = instr {
                self.compile_instruction(main_fn, instr).unwrap();
            }
        }
        // Restore builder to main entry before compiling main instructions
        self.builder.position_at_end(entry_bb);

        // 2) Compile non-function-definition instructions
        for instr in &self.instructions {
            if !matches!(instr, Instruction::FunctionDef { .. }) {
                self.compile_instruction(main_fn, instr).unwrap();
            }
        }
        // Restore builder to main entry before inserting default return
        if let Some(last_block) = self.builder.get_insert_block() {
            if last_block.get_terminator().is_none() {
                self.builder
                    .build_return(Some(&f64_type.const_float(0.0)))
                    .unwrap();
            }
        }

        // Verify the module before handing it to the JIT so we surface IR issues
        if let Err(err) = self.module.verify() {
            eprintln!("LLVM IR verification failed:\n{}", err.to_string());
            self.module.print_to_stderr();
            return None;
        }

        // Ensure C library functions are resolved at runtime to prevent segfaults
        let strcmp_fn = self.get_or_create_strcmp();
        self.execution_engine
            .add_global_mapping(&strcmp_fn, strcmp as usize);
        let strncmp_fn = self.get_or_create_strncmp();
        self.execution_engine
            .add_global_mapping(&strncmp_fn, strncmp as usize);
        let printf_fn = self.get_or_create_printf();
        self.execution_engine
            .add_global_mapping(&printf_fn, printf as usize);
        let malloc_fn = self.get_or_create_malloc();
        self.execution_engine
            .add_global_mapping(&malloc_fn, malloc as usize);
        let strcpy_fn = self.get_or_create_strcpy();
        self.execution_engine
            .add_global_mapping(&strcpy_fn, strcpy as usize);
        let strcat_fn = self.get_or_create_strcat_c();
        self.execution_engine
            .add_global_mapping(&strcat_fn, strcat as usize);
        let strlen_fn = self.get_or_create_strlen();
        self.execution_engine
            .add_global_mapping(&strlen_fn, strlen as usize);
        let realloc_fn = self.get_or_create_realloc();
        self.execution_engine
            .add_global_mapping(&realloc_fn, realloc as usize);
        let atoi_fn = self.get_or_create_atoi();
        self.execution_engine
            .add_global_mapping(&atoi_fn, atoi as usize);
        let strstr_fn = self.get_or_create_strstr();
        self.execution_engine
            .add_global_mapping(&strstr_fn, strstr as usize);
        let str_replace_fn = self.get_or_create_str_replace();
        self.execution_engine
            .add_global_mapping(&str_replace_fn, qs_str_replace as usize);
        let str_split_fn = self.get_or_create_str_split();
        self.execution_engine
            .add_global_mapping(&str_split_fn, qs_str_split as usize);
        let sprintf_fn = self.get_or_create_sprintf();
        self.execution_engine
            .add_global_mapping(&sprintf_fn, sprintf as usize);
        let rand_fn = self.get_or_create_rand();
        self.execution_engine
            .add_global_mapping(&rand_fn, rand as usize);

        let fopen_fn = self.get_or_create_fopen();
        self.execution_engine
            .add_global_mapping(&fopen_fn, fopen as usize);
        let fread_fn = self.get_or_create_fread();
        self.execution_engine
            .add_global_mapping(&fread_fn, fread as usize);
        let fwrite_fn = self.get_or_create_fwrite();
        self.execution_engine
            .add_global_mapping(&fwrite_fn, fwrite as usize);
        let fclose_fn = self.get_or_create_fclose();
        self.execution_engine
            .add_global_mapping(&fclose_fn, fclose as usize);
        let get_stdin_fn = self.get_or_create_get_stdin();
        self.execution_engine
            .add_global_mapping(&get_stdin_fn, get_stdin as usize);

        let qs_lst_cb = self.get_or_create_qs_listen_with_callback();
        self.execution_engine
            .add_global_mapping(&qs_lst_cb, qs_listen_with_callback as usize);

        // Map Request object functions
        let create_req = self.get_or_create_create_request_object();
        self.execution_engine
            .add_global_mapping(&create_req, create_request_object as usize);
        let get_method = self.get_or_create_get_request_method();
        self.execution_engine
            .add_global_mapping(&get_method, get_request_method as usize);
        let get_path = self.get_or_create_get_request_path();
        self.execution_engine
            .add_global_mapping(&get_path, get_request_path as usize);
        // Additional Request getters
        let get_body = self.get_or_create_get_request_body();
        self.execution_engine
            .add_global_mapping(&get_body, get_request_body as usize);
        let get_query = self.get_or_create_get_request_query();
        self.execution_engine
            .add_global_mapping(&get_query, get_request_query as usize);
        let get_headers = self.get_or_create_get_request_headers();
        self.execution_engine
            .add_global_mapping(&get_headers, get_request_headers as usize);

        // Map Web helper functions
        let web_helper = self.get_or_create_web_helper();
        self.execution_engine
            .add_global_mapping(&web_helper, create_web_helper as usize);
        let range_builder = self.get_or_create_range_builder();
        self.execution_engine
            .add_global_mapping(&range_builder, create_range_builder as usize);
        let create_range_builder_to = self.get_or_create_range_builder_to();
        self.execution_engine
            .add_global_mapping(&create_range_builder_to, range_builder_to as usize);
        self.execution_engine
            .add_global_mapping(&range_builder, create_range_builder as usize);
        let create_range_builder_from = self.get_or_create_range_builder_from();
        self.execution_engine
            .add_global_mapping(&create_range_builder_from, range_builder_from as usize);

        let create_range_builder_step = self.get_or_create_range_builder_step();
        self.execution_engine
            .add_global_mapping(&create_range_builder_step, range_builder_step as usize);

        let range_get_from = self.get_or_create_range_builder_get_from();
        self.execution_engine
            .add_global_mapping(&range_get_from, range_builder_get_from as usize);
        let range_get_to = self.get_or_create_range_builder_get_to();
        self.execution_engine
            .add_global_mapping(&range_get_to, range_builder_get_to as usize);
        let range_get_step = self.get_or_create_range_builder_get_step();
        self.execution_engine
            .add_global_mapping(&range_get_step, range_builder_get_step as usize);

        let io_read = self.get_or_create_io_read_file();
        self.execution_engine
            .add_global_mapping(&io_read, io_read_file as usize);

        let io_write = self.get_or_create_io_write_file();
        self.execution_engine
            .add_global_mapping(&io_write, io_write_file as usize);
        let web_text_fn = self.get_or_create_web_text();
        self.execution_engine
            .add_global_mapping(&web_text_fn, web_text as usize);
        let web_page_fn = self.get_or_create_web_page();
        self.execution_engine
            .add_global_mapping(&web_page_fn, web_page as usize);
        // Map web.file correctly (was incorrectly mapped to web_page symbol)
        let web_file_fn = self.get_or_create_web_file();
        self.execution_engine
            .add_global_mapping(&web_file_fn, web_file as usize);
        // Map web.json
        let web_json_fn = self.get_or_create_web_json();
        self.execution_engine
            .add_global_mapping(&web_json_fn, web_json as usize);
        let web_error_text_fn = self.get_or_create_web_error_text();
        self.execution_engine
            .add_global_mapping(&web_error_text_fn, web_error_text as usize);
        let web_error_page_fn = self.get_or_create_web_error_page();
        self.execution_engine
            .add_global_mapping(&web_error_page_fn, web_error_page as usize);
        let web_redirect_fn = self.get_or_create_web_redirect();
        self.execution_engine
            .add_global_mapping(&web_redirect_fn, web_redirect as usize);

        // Map Obj (Kv) functions
        let obj_new_fn = self.get_or_create_qs_obj_new();
        self.execution_engine
            .add_global_mapping(&obj_new_fn, qs_obj_new as usize);
        let obj_insert_fn = self.get_or_create_qs_obj_insert_str();
        self.execution_engine
            .add_global_mapping(&obj_insert_fn, qs_obj_insert_str as usize);
        let obj_get_fn = self.get_or_create_qs_obj_get_str();
        self.execution_engine
            .add_global_mapping(&obj_get_fn, qs_obj_get_str as usize);

        match unsafe { self.execution_engine.get_function::<SumFunc>("main") } {
            Ok(func) => Some(func),
            Err(FunctionLookupError::FunctionNotFound) => {
                eprintln!("Failed to JIT program, update cli and try again");
                None
            }
            Err(FunctionLookupError::JITNotEnabled) => {
                eprintln!("Failed to JIT main(): JIT not enabled on execution engine");
                None
            }
        }
    }

    fn compile_instruction(
        &self,
        function: FunctionValue<'ctx>,
        instr: &Instruction,
    ) -> Result<(), BuilderError> {
        match instr {
            Instruction::If {
                condition,
                then,
                elses,
            } => {
                // Create blocks
                let then_bb = self.context.append_basic_block(function, "then");
                let else_bb = self.context.append_basic_block(function, "else");
                let cont_bb = self.context.append_basic_block(function, "cont");
                // Build branch on condition
                let BasicValueEnum::IntValue(cond_val) = self.compile_expr(condition)? else {
                    panic!("{condition:?}")
                };
                self.builder
                    .build_conditional_branch(cond_val, then_bb, else_bb)?;
                // Then block
                self.builder.position_at_end(then_bb);
                for stmt in then {
                    self.compile_instruction(function, stmt)?;
                }
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(cont_bb)?;
                }
                // Else block
                self.builder.position_at_end(else_bb);
                if let Some(else_node) = elses {
                    self.compile_instruction(function, else_node)?;
                }
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(cont_bb)?;
                }
                // Continue here
                self.builder.position_at_end(cont_bb);
                Ok(())
            }
            Instruction::Expr(expr) => {
                let _ = self.compile_expr(expr)?;
                Ok(())
            }
            Instruction::Return(expr) => {
                // In 'main', treat expression statements (calls) as side effects rather than returns
                let fn_name = function.get_name().to_str().unwrap();
                if fn_name == "main" {
                    // Evaluate for side effects (e.g., calling functions, printing)
                    let _ = self.compile_expr(expr)?;
                } else {
                    // True return inside a user-defined function
                    let ret_val = self.compile_expr(expr)?;
                    self.builder.build_return(Some(&ret_val))?;
                }
                Ok(())
            }
            Instruction::Block(b) => {
                let saved_quick = self.quick_var_types.borrow().clone();
                for i in b {
                    self.compile_instruction(function, i)?;
                }
                *self.quick_var_types.borrow_mut() = saved_quick;
                Ok(())
            }
            Instruction::Break => {
                let break_block = {
                    let stack = self.loop_stack.borrow();
                    stack
                        .last()
                        .cloned()
                        .expect("`break` used outside of a loop")
                        .break_block
                };
                self.builder.build_unconditional_branch(break_block)?;
                let after_break = self.context.append_basic_block(function, "after.break");
                self.builder.position_at_end(after_break);
                Ok(())
            }
            Instruction::Let {
                name,
                value,
                global,
                type_hint,
            } => {
                let init_val = self.compile_expr(value)?;
                let value_ty = init_val.get_type();
                // Keep Quick type metadata in sync so later property accesses know the static type.
                self.quick_var_types
                    .borrow_mut()
                    .insert(name.clone(), type_hint.clone());

                if *global {
                    // Compute the declared LLVM type for the binding so the global matches static typing
                    let llvm_ty = self.qtype_to_llvm(type_hint);
                    let global =
                        self.module
                            .add_global(llvm_ty, Some(AddressSpace::default()), name);

                    // Zero-initialize globals so the verifier accepts the module (non-constant init happens at runtime)
                    let zero_init = match &llvm_ty {
                        BasicTypeEnum::ArrayType(t) => t.const_zero().as_basic_value_enum(),
                        BasicTypeEnum::FloatType(t) => t.const_zero().as_basic_value_enum(),
                        BasicTypeEnum::IntType(t) => t.const_zero().as_basic_value_enum(),
                        BasicTypeEnum::PointerType(t) => t.const_null().as_basic_value_enum(),
                        BasicTypeEnum::StructType(t) => t.const_zero().as_basic_value_enum(),
                        BasicTypeEnum::VectorType(t) => t.const_zero().as_basic_value_enum(),
                        BasicTypeEnum::ScalableVectorType(t) => {
                            t.const_zero().as_basic_value_enum()
                        }
                    };
                    global.set_initializer(&zero_init);

                    // Populate the global at runtime with the actual value
                    self.builder
                        .build_store(global.as_pointer_value(), init_val)?;

                    self.vars
                        .borrow_mut()
                        .insert(name.clone(), global.as_pointer_value());
                    self.var_types.borrow_mut().insert(name.clone(), llvm_ty);
                } else {
                    // Local path: hoist allocas to function entry
                    let entry = function.get_first_basic_block().unwrap();
                    let temp_builder = self.context.create_builder();
                    match entry.get_first_instruction() {
                        Some(inst) => temp_builder.position_before(&inst),
                        None => temp_builder.position_at_end(entry),
                    }

                    let ptr = temp_builder.build_alloca(value_ty, name).unwrap();
                    self.builder.build_store(ptr, init_val)?;
                    self.vars.borrow_mut().insert(name.clone(), ptr);
                    self.var_types.borrow_mut().insert(name.clone(), value_ty);
                }

                Ok(())
            }
            Instruction::For {
                iterator,
                range,
                body,
            } => {
                let saved_quick = self.quick_var_types.borrow().clone();
                self.quick_var_types
                    .borrow_mut()
                    .insert(iterator.clone(), Type::Num);
                let range_val = self.compile_expr(range)?;
                let range_ptr = match range_val {
                    BasicValueEnum::PointerValue(p) => p,
                    other => {
                        panic!("Range builder expression did not compile to a pointer: {other:?}")
                    }
                };

                let get_from = self.get_or_create_range_builder_get_from();
                let get_to = self.get_or_create_range_builder_get_to();
                let get_step = self.get_or_create_range_builder_get_step();

                let from_f = self
                    .builder
                    .build_call(get_from, &[range_ptr.into()], "range_from")?
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_float_value();
                let to_f = self
                    .builder
                    .build_call(get_to, &[range_ptr.into()], "range_to")?
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_float_value();
                let step_f = self
                    .builder
                    .build_call(get_step, &[range_ptr.into()], "range_step")?
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_float_value();

                let f64_ty = self.context.f64_type();

                // Allocate loop variable in entry block
                let entry = function.get_first_basic_block().unwrap();
                let temp_builder = self.context.create_builder();
                match entry.get_first_instruction() {
                    Some(inst) => temp_builder.position_before(&inst),
                    None => temp_builder.position_at_end(entry),
                }
                let iter_alloca = temp_builder
                    .build_alloca(f64_ty.as_basic_type_enum(), iterator.as_str())
                    .unwrap();
                self.vars.borrow_mut().insert(iterator.clone(), iter_alloca);
                self.var_types
                    .borrow_mut()
                    .insert(iterator.clone(), f64_ty.as_basic_type_enum());

                // Initialize iterator
                self.builder.build_store(iter_alloca, from_f)?;

                let cond_bb = self.context.append_basic_block(function, "for.cond");
                let body_bb = self.context.append_basic_block(function, "for.body");
                let step_bb = self.context.append_basic_block(function, "for.step");
                let cont_bb = self.context.append_basic_block(function, "for.cont");

                let loop_ctx = LoopContext {
                    break_block: cont_bb,
                    _continue_block: step_bb,
                };
                let _loop_scope = LoopScopeGuard::new(&self.loop_stack, loop_ctx);

                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(cond_bb)?;
                }

                // condition block
                self.builder.position_at_end(cond_bb);
                let current_val = self
                    .builder
                    .build_load(f64_ty, iter_alloca, "for_iter")?
                    .into_float_value();
                let zero = f64_ty.const_float(0.0);
                let step_positive = self.builder.build_float_compare(
                    FloatPredicate::OGT,
                    step_f,
                    zero,
                    "step_pos",
                )?;
                let step_negative = self.builder.build_float_compare(
                    FloatPredicate::OLT,
                    step_f,
                    zero,
                    "step_neg",
                )?;
                let cond_pos = self.builder.build_float_compare(
                    FloatPredicate::OLT,
                    current_val,
                    to_f,
                    "for_lt",
                )?;
                let cond_neg = self.builder.build_float_compare(
                    FloatPredicate::OGT,
                    current_val,
                    to_f,
                    "for_gt",
                )?;

                let bool_ty = self.context.bool_type();
                let cond_neg_or_zero = self
                    .builder
                    .build_select(
                        step_negative,
                        cond_neg.as_basic_value_enum(),
                        bool_ty.const_zero().as_basic_value_enum(),
                        "cond_neg_or_zero",
                    )?
                    .into_int_value();
                let cond = self
                    .builder
                    .build_select(
                        step_positive,
                        cond_pos.as_basic_value_enum(),
                        cond_neg_or_zero.as_basic_value_enum(),
                        "for_cond_sel",
                    )?
                    .into_int_value();
                self.builder
                    .build_conditional_branch(cond, body_bb, cont_bb)?;

                // body block
                self.builder.position_at_end(body_bb);
                for stmt in body {
                    self.compile_instruction(function, stmt)?;
                }
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(step_bb)?;
                }

                // step block
                self.builder.position_at_end(step_bb);
                let iter_val = self
                    .builder
                    .build_load(f64_ty, iter_alloca, "for_iter_step")?
                    .into_float_value();
                let next_val = self
                    .builder
                    .build_float_add(iter_val, step_f, "for_iter_next")?;
                self.builder.build_store(iter_alloca, next_val)?;
                self.builder.build_unconditional_branch(cond_bb)?;

                // continuation
                self.builder.position_at_end(cont_bb);
                *self.quick_var_types.borrow_mut() = saved_quick;
                Ok(())
            }
            Instruction::Assign(target, new_val, _typ) => {
                match target {
                    Expr::Variable(name) => {
                        // Optimization: var = var + something
                        if let Expr::Binary(left_expr, BinOp::Plus, right_expr) = new_val {
                            if let Expr::Variable(var_name) = left_expr.as_ref() {
                                if var_name == name {
                                    return self.compile_safe_string_append(name, right_expr);
                                }
                            }
                        }

                        let new_c = self.compile_expr(new_val)?;
                        let ptr_opt = {
                            let vars_ref = self.vars.borrow();
                            vars_ref.get(name).copied()
                        };

                        match ptr_opt {
                            Some(ptr) => {
                                self.builder.build_store(ptr, new_c)?;
                                if let Some(descriptor) = self.get_active_capture_descriptor(name) {
                                    if let Some(global) =
                                        self.module.get_global(&descriptor.global_name)
                                    {
                                        let ptr_ty = self.context.ptr_type(AddressSpace::default());
                                        let env_ptr = self
                                            .builder
                                            .build_load(
                                                ptr_ty,
                                                global.as_pointer_value(),
                                                &format!("{name}_env_ptr_store"),
                                            )?
                                            .into_pointer_value();
                                        self.builder.build_store(env_ptr, new_c)?;
                                    }
                                }
                                Ok(())
                            }
                            None => {
                                if let Some(descriptor) = self.get_active_capture_descriptor(name) {
                                    if let Some(global) =
                                        self.module.get_global(&descriptor.global_name)
                                    {
                                        let ptr_ty = self.context.ptr_type(AddressSpace::default());
                                        let env_ptr = self
                                            .builder
                                            .build_load(
                                                ptr_ty,
                                                global.as_pointer_value(),
                                                &format!("{name}_env_ptr_store"),
                                            )?
                                            .into_pointer_value();
                                        self.builder.build_store(env_ptr, new_c)?;
                                        Ok(())
                                    } else {
                                        panic!("Capture global missing for {name}");
                                    }
                                } else {
                                    panic!("Variable not found: {name}");
                                }
                            }
                        }
                    }
                    Expr::Get(obj_expr, prop) => {
                        let obj_val = self.compile_expr(obj_expr)?;
                        let obj_ptr = match obj_val {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!("Property assignment on non-pointer value: {other:?}"),
                        };

                        let var_name = if let Expr::Variable(name) = &**obj_expr {
                            name
                        } else {
                            panic!("Property assignment requires variable receiver");
                        };

                        let custom_type = match self
                            .lookup_qtype(var_name)
                            .unwrap_or_else(|| panic!("Unknown type for object {var_name}"))
                        {
                            Type::Custom(ct) => ct,
                            _ => panic!("Property assignment supported only on custom objects"),
                        };

                        let binding = self.pctx.borrow();
                        let type_name = binding
                            .types
                            .iter()
                            .find(|(_, def)| **def == custom_type)
                            .map(|(k, _)| k.clone())
                            .unwrap();
                        let Custype::Object(field_defs) = &binding.types[&type_name] else {
                            panic!("Expected object type");
                        };
                        let field_type = field_defs
                            .get(prop)
                            .unwrap_or_else(|| panic!("Unknown property {prop} on {type_name}"))
                            .clone();
                        let field_index = field_defs
                            .keys()
                            .position(|k| k == prop)
                            .unwrap_or_else(|| panic!("Unknown property {prop} on {type_name}"))
                            as u64;

                        drop(binding);

                        let idx_const = self.context.i64_type().const_int(field_index, false);
                        let field_ptr = unsafe {
                            self.builder.build_in_bounds_gep(
                                self.context.i64_type(),
                                obj_ptr,
                                &[idx_const],
                                &format!("store_{}", prop),
                            )?
                        };

                        let value = self.compile_expr(new_val)?;
                        match field_type.unwrap() {
                            Type::Num => {
                                let val = match value {
                                    BasicValueEnum::FloatValue(f) => f,
                                    BasicValueEnum::IntValue(i) => {
                                        self.builder.build_signed_int_to_float(
                                            i,
                                            self.context.f64_type(),
                                            "prop_num_cast",
                                        )?
                                    }
                                    other => panic!(
                                        "Cannot assign non-number {other:?} to numeric field"
                                    ),
                                };
                                self.builder.build_store(field_ptr, val)?;
                            }
                            Type::Str | Type::List(_) | Type::Custom(_) => {
                                let ptr_val = match value {
                                    BasicValueEnum::PointerValue(p) => p,
                                    other => panic!(
                                        "Expected pointer value for property {prop}, got {other:?}"
                                    ),
                                };
                                self.builder.build_store(field_ptr, ptr_val)?;
                            }
                            Type::Bool => {
                                let bool_val = match value {
                                    BasicValueEnum::IntValue(i) => i,
                                    other => panic!(
                                        "Expected boolean value for property {prop}, got {other:?}"
                                    ),
                                };
                                self.builder.build_store(field_ptr, bool_val)?;
                            }
                            other => panic!("Unsupported property assignment type: {other:?}"),
                        }
                        Ok(())
                    }
                    Expr::Index(list_expr, idx_expr) => {
                        let list_val = self.compile_expr(list_expr)?;
                        let list_ptr = match list_val {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!("Index assignment on non-pointer value: {other:?}"),
                        };

                        let index_val = self.compile_expr(idx_expr)?;
                        let i64_ty = self.context.i64_type();
                        let idx_i64 = match index_val {
                            BasicValueEnum::IntValue(i) => i,
                            BasicValueEnum::FloatValue(f) => self
                                .builder
                                .build_float_to_signed_int(f, i64_ty, "index_cast")?,
                            other => panic!("Index must be numeric, got {other:?}"),
                        };

                        let list_type = self
                            .infer_expr_type(list_expr)
                            .unwrap_or_else(|e| panic!("{e}"));
                        let Type::List(inner) = list_type else {
                            panic!("Index assignment only supported on lists");
                        };

                        let one = i64_ty.const_int(1, false);
                        let idx_with_offset =
                            self.builder.build_int_add(idx_i64, one, "idx_plus1")?;
                        let elem_ptr = unsafe {
                            self.builder.build_in_bounds_gep(
                                self.context.f64_type(),
                                list_ptr,
                                &[idx_with_offset],
                                "list_store",
                            )?
                        };

                        let value = self.compile_expr(new_val)?;
                        match inner.unwrap() {
                            Type::Num => {
                                let val = match value {
                                    BasicValueEnum::FloatValue(f) => f,
                                    BasicValueEnum::IntValue(i) => {
                                        self.builder.build_signed_int_to_float(
                                            i,
                                            self.context.f64_type(),
                                            "list_num_cast",
                                        )?
                                    }
                                    other => {
                                        panic!("Cannot assign {other:?} to numeric list element")
                                    }
                                };
                                self.builder.build_store(elem_ptr, val)?;
                            }
                            Type::Str => {
                                let ptr_val = match value {
                                    BasicValueEnum::PointerValue(p) => p,
                                    other => panic!(
                                        "Cannot assign non-pointer {other:?} to string list element"
                                    ),
                                };
                                self.builder.build_store(elem_ptr, ptr_val)?;
                            }
                            other => {
                                panic!("List assignment not supported for inner type {other:?}")
                            }
                        }
                        Ok(())
                    }
                    other => panic!("Unsupported assignment target: {other:?}"),
                }
            }
            // in your compile_instruction:
            Instruction::Println(expr) => {
                let val = self.compile_expr(expr)?;
                let printf_fn = self.get_or_create_printf();

                match val {
                    BasicValueEnum::PointerValue(p) => {
                        // string case
                        let fmt = self
                            .builder
                            .build_global_string_ptr("%s\n\0", "fmt_s")
                            .unwrap();
                        self.builder.build_call(
                            printf_fn,
                            &[fmt.as_pointer_value().into(), p.into()],
                            "printf_str",
                        )?;
                    }
                    BasicValueEnum::FloatValue(i) => {
                        // numeric case
                        let fmt = self
                            .builder
                            .build_global_string_ptr("%f\n\0", "fmt_d")
                            .unwrap();
                        self.builder.build_call(
                            printf_fn,
                            &[fmt.as_pointer_value().into(), i.into()],
                            "printf_int",
                        )?;
                    }
                    BasicValueEnum::IntValue(i) => {
                        let bit_width = i.get_type().get_bit_width();
                        if bit_width == 1 {
                            // boolean case; select "true"/"false"
                            let fmt = self
                                .builder
                                .build_global_string_ptr("%s\n\0", "fmt_b")
                                .unwrap();
                            let true_str = self
                                .builder
                                .build_global_string_ptr("true\0", "bool_true")
                                .unwrap();
                            let false_str = self
                                .builder
                                .build_global_string_ptr("false\0", "bool_false")
                                .unwrap();
                            let bool_text = self
                                .builder
                                .build_select(
                                    i,
                                    true_str.as_pointer_value().as_basic_value_enum(),
                                    false_str.as_pointer_value().as_basic_value_enum(),
                                    "bool_str",
                                )?
                                .into_pointer_value();
                            self.builder.build_call(
                                printf_fn,
                                &[fmt.as_pointer_value().into(), bool_text.into()],
                                "printf_bool",
                            )?;
                        } else {
                            // other integers; normalize to 64-bit and print
                            let fmt = self
                                .builder
                                .build_global_string_ptr("%ld\n\0", "fmt_i")
                                .unwrap();
                            let i64_ty = self.context.i64_type();
                            let widened = if bit_width < 64 {
                                self.builder
                                    .build_int_s_extend(i, i64_ty, "print_int_sext")?
                            } else if bit_width > 64 {
                                self.builder
                                    .build_int_truncate(i, i64_ty, "print_int_trunc")?
                            } else {
                                i
                            };
                            self.builder.build_call(
                                printf_fn,
                                &[fmt.as_pointer_value().into(), widened.into()],
                                "printf_int",
                            )?;
                        }
                    }
                    other => panic!("Unsupported value passed to print: {other:?}"),
                }
                Ok(())
            }
            Instruction::FunctionDef {
                name,
                params,
                return_type,
                body,
            } => {
                // Save current variable scopes to avoid leaking anon-fn parameters into caller
                let saved_vars = self.vars.borrow().clone();
                let saved_var_types = self.var_types.borrow().clone();
                let saved_quick = self.quick_var_types.borrow().clone();
                let capture_map = self.closure_envs.borrow().get(name).cloned();
                let _function_scope = FunctionScopeGuard::new(&self.current_function, name.clone());

                // Ensure the function is declared before emitting the body so it can be
                // referenced by other functions (including modules) during compilation.
                let function = self.declare_function(name, params, return_type);
                debug_assert!(
                    function.get_first_basic_block().is_none(),
                    "Function `{}` emitted twice",
                    name
                );

                // Create entry block and position builder
                let entry_bb = self.context.append_basic_block(function, "entry");
                self.builder.position_at_end(entry_bb);

                // Allocate space for each parameter and store the incoming values
                for (i, (param_name, typ)) in params.iter().enumerate() {
                    let arg = function.get_nth_param(i as u32).unwrap();
                    // Cast to basic value
                    //let arg_val = arg.into();
                    let ptr = self
                        .builder
                        .build_alloca(arg.get_type(), param_name)
                        .unwrap();
                    self.builder.build_store(ptr, arg)?;
                    self.vars.borrow_mut().insert(param_name.clone(), ptr);
                    // Map AST Type to LLVM BasicTypeEnum for parameter
                    let param_elem_type = self.qtype_to_llvm(typ);
                    self.var_types
                        .borrow_mut()
                        .insert(param_name.clone(), param_elem_type);
                    self.quick_var_types
                        .borrow_mut()
                        .insert(param_name.clone(), typ.clone());
                }

                if let Some(captures) = capture_map.as_ref() {
                    let ptr_ty = self.context.ptr_type(AddressSpace::default());
                    for (captured_name, descriptor) in captures {
                        let capture_alloca = self
                            .builder
                            .build_alloca(descriptor.ty, captured_name)
                            .unwrap();
                        if let Some(global) = self.module.get_global(&descriptor.global_name) {
                            let env_ptr = self
                                .builder
                                .build_load(
                                    ptr_ty,
                                    global.as_pointer_value(),
                                    &format!("{captured_name}_env_ptr"),
                                )?
                                .into_pointer_value();
                            let captured_val = self.builder.build_load(
                                descriptor.ty,
                                env_ptr,
                                &format!("{captured_name}_env_val"),
                            )?;
                            self.builder.build_store(capture_alloca, captured_val)?;
                        }
                        self.vars
                            .borrow_mut()
                            .insert(captured_name.clone(), capture_alloca);
                        self.var_types
                            .borrow_mut()
                            .insert(captured_name.clone(), descriptor.ty);
                    }
                }

                // Compile the body of the function
                for instr in body {
                    self.compile_instruction(function, instr)?;
                }

                // Ensure the function has a terminator; default to a sensible zero/null value.
                if let Some(current_block) = self.builder.get_insert_block() {
                    if current_block.get_terminator().is_none() {
                        match function.get_type().get_return_type() {
                            Some(BasicTypeEnum::FloatType(float_ty)) => {
                                let zero = float_ty.const_float(0.0);
                                self.builder.build_return(Some(&zero))?;
                            }
                            Some(BasicTypeEnum::IntType(int_ty)) => {
                                let zero = int_ty.const_zero();
                                self.builder.build_return(Some(&zero))?;
                            }
                            Some(BasicTypeEnum::PointerType(ptr_ty)) => {
                                let null = ptr_ty.const_null();
                                self.builder.build_return(Some(&null))?;
                            }
                            Some(BasicTypeEnum::StructType(_))
                            | Some(BasicTypeEnum::VectorType(_))
                            | Some(BasicTypeEnum::ArrayType(_))
                            | Some(BasicTypeEnum::ScalableVectorType(_)) => {
                                unreachable!(
                                    "Unhandled default return for complex type in function `{name}`"
                                );
                            }
                            None => {
                                self.builder.build_return(None)?;
                            }
                        }
                    }
                }

                // Restore previous variable scopes
                *self.vars.borrow_mut() = saved_vars;
                *self.var_types.borrow_mut() = saved_var_types;
                *self.quick_var_types.borrow_mut() = saved_quick;
                Ok(())
            }
            Instruction::Maybe(maybe, block, otherwise) => {
                let saved_quick = match maybe {
Expr::Variable(var_name) =>{
                let var_name = var_name.clone();
                let saved_quick = self.quick_var_types.borrow().clone();
                if let Some(Type::Option(inner)) = saved_quick.get(&var_name).cloned() {
                    self.quick_var_types
                        .borrow_mut()
                        .insert(var_name.clone(), (*inner).clone());
                }
                saved_quick
                }
                other =>self.quick_var_types.borrow().clone()
                };
                // let Expr::Variable(var_name) = maybe else {
                //     unreachable!()
                // };

                // Evaluate the maybe expression
                let val = self.compile_expr(maybe)?;
                // Build a nil comparison: non-nil => true branch
                let cond = match val {
                    BasicValueEnum::PointerValue(ptr) => {
                        // Null pointer for nil
                        let null_ptr = self.context.ptr_type(AddressSpace::default()).const_null();
                        self.builder
                            .build_int_compare(IntPredicate::NE, ptr, null_ptr, "neq_nil")
                    }
                    BasicValueEnum::FloatValue(iv) => {
                        // Zero integer for nil
                        let zero = self.context.f64_type().const_float(0.0);
                        self.builder
                            .build_float_compare(FloatPredicate::ONE, iv, zero, "neq_nil")
                    }
                    BasicValueEnum::IntValue(i) => {
                        let zero = self.context.f64_type().const_float(0.0);
                        self.builder.build_float_compare(
                            FloatPredicate::ONE,
                            self.builder.build_signed_int_to_float(
                                i,
                                self.context.f64_type(),
                                "int_to_float",
                            )?,
                            zero,
                            "neq_nil",
                        )
                    }
                    _ => panic!("Unsupported type in maybe: {val}"),
                }?;

                // Blocks for then, else, and continuation
                let then_block = self.context.append_basic_block(function, "then");
                let else_block = self.context.append_basic_block(function, "else");
                let after_block = self.context.append_basic_block(function, "after");
                // Branch on non-nil
                self.builder
                    .build_conditional_branch(cond, then_block, else_block)?;

                // Then block (value is non-nil)
                self.builder.position_at_end(then_block);
                self.compile_instruction(function, block)?;
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(after_block)?;
                }

                // Else block (value is nil)
                *self.quick_var_types.borrow_mut() = saved_quick.clone();
                self.builder.position_at_end(else_block);
                if let Some(else_node) = otherwise {
                    self.compile_instruction(function, else_node)?;
                }
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(after_block)?;
                }

                // Continue after maybe
                *self.quick_var_types.borrow_mut() = saved_quick;
                self.builder.position_at_end(after_block);
                Ok(())
            }
            Instruction::While { condition, body } => {
                let cond_bb = self.context.append_basic_block(function, "while.cond");
                let body_bb = self.context.append_basic_block(function, "while.body");
                let cont_bb = self.context.append_basic_block(function, "while.cont");

                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(cond_bb)?;
                }

                self.builder.position_at_end(cond_bb);
                let BasicValueEnum::IntValue(cond_val) = self.compile_expr(condition)? else {
                    panic!()
                };
                self.builder
                    .build_conditional_branch(cond_val, body_bb, cont_bb)?;

                let loop_ctx = LoopContext {
                    break_block: cont_bb,
                    _continue_block: cond_bb,
                };
                let _loop_scope = LoopScopeGuard::new(&self.loop_stack, loop_ctx);

                self.builder.position_at_end(body_bb);
                for stmt in body {
                    self.compile_instruction(function, stmt)?;
                }
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(cond_bb)?;
                }

                self.builder.position_at_end(cont_bb);
                Ok(())
            }
            Instruction::Use {
                module_name,
                mod_path,
            } => Ok(()),
            Instruction::Match { expr, arms } => {
                let scrutinee_type = self.infer_expr_type(expr).unwrap();
                let mut else_branch: Option<Instruction> = None;

                enum MatchKind {
                    NeedsCatchAll,
                    Bool,
                    Enum { variants: Vec<String> },
                }

                let match_kind = match scrutinee_type.clone() {
                    Type::Num | Type::Str => MatchKind::NeedsCatchAll,
                    Type::Bool => MatchKind::Bool,
                    Type::Custom(Custype::Enum(variants)) => MatchKind::Enum { variants },
                    other => {
                        eprintln!("Can't match on a {other:?}");
                        std::process::exit(70);
                    }
                };

                let mut saw_catchall = false;
                let mut saw_true = false;
                let mut saw_false = false;
                let mut seen_variants: HashSet<String> = HashSet::new();

                for arm in arms {
                    match arm {
                        MatchArm::CatchAll(_, _) => {
                            saw_catchall = true;
                            break;
                        }
                        MatchArm::Literal(pattern, _) => match (&match_kind, pattern) {
                            (MatchKind::Bool, Expr::Literal(Value::Bool(true))) => saw_true = true,
                            (MatchKind::Bool, Expr::Literal(Value::Bool(false))) => {
                                saw_false = true;
                            }
                            (MatchKind::Bool, other) => {
                                eprintln!("{other:?} is not a valid match arm for Bool type");
                                std::process::exit(70);
                            }
                            (MatchKind::Enum { .. }, Expr::Get(enum_expr, variant)) => {
                                if !matches!(**enum_expr, Expr::Variable(_)) {
                                    eprintln!(
                                        "Enum match arms must reference a variant like Type.Variant"
                                    );
                                    std::process::exit(70);
                                }
                                seen_variants.insert(variant.clone());
                            }
                            (MatchKind::Enum { .. }, other) => {
                                eprintln!(
                                    "{other:?} is not a valid enum variant in this match statement"
                                );
                                std::process::exit(70);
                            }
                            _ => {}
                        },
                    }
                }

                match match_kind {
                    MatchKind::NeedsCatchAll => {
                        if !saw_catchall {
                            eprintln!("All variants of {scrutinee_type:?} not covered in match statement");
                            std::process::exit(70);
                        }
                    }
                    MatchKind::Bool => {
                        if !saw_catchall && !(saw_true && saw_false) {
                            eprintln!("Boolean match must handle both true and false or provide a catch-all arm");
                            std::process::exit(70);
                        }
                    }
                    MatchKind::Enum { variants } => {
                        if !saw_catchall {
                            let missing: Vec<_> = variants
                                .iter()
                                .filter(|name| !seen_variants.contains(*name))
                                .cloned()
                                .collect();
                            if !missing.is_empty() {
                                eprintln!(
                                    "Match missing enum variant arm(s): {}",
                                    missing.join(", ")
                                );
                                std::process::exit(70);
                            }
                        }
                    }
                }
                for arm in arms.iter().rev() {
                    match arm {
                        MatchArm::Literal(pattern, runs) => {
                            let condition = Expr::Binary(
                                Box::new(expr.clone()),
                                BinOp::EqEq,
                                Box::new(pattern.clone()),
                            );
                            let new_if = Instruction::If {
                                condition,
                                then: vec![runs.clone()],
                                elses: else_branch.take().map(Box::new),
                            };
                            else_branch = Some(new_if);
                        }
                        MatchArm::CatchAll(name,  runs) => {
                            let binding = Instruction::Let {
                                name: name.clone(),
                                value: expr.clone(),
                                type_hint: scrutinee_type.clone(),
                                global: false,
                            };
                            let mut block_instrs = vec![binding];
                            block_instrs.push(runs.clone());
                            else_branch = Some(Instruction::Block(block_instrs));
                        }
                    }
                }
                if let Some(final_instr) = else_branch {
                    self.compile_instruction(function, &final_instr)
                } else {
                    Ok(())
                }
            }
            Instruction::Nothing => Ok(()),
            l => unimplemented!("{:#?}", l),
        }
    }

    fn get_or_create_fopen(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("fopen") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            // fopen signature: (i8*, i8*) -> void*
            let fn_type = void_ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false);
            self.module.add_function("fopen", fn_type, None)
        }
    }

    fn get_or_create_fread(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("fread") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            // fread signature: (i8*, i64, i64, void*) -> i64
            let fn_type = i64_type.fn_type(
                &[
                    i8ptr.into(),
                    i64_type.into(),
                    i64_type.into(),
                    void_ptr.into(),
                ],
                false,
            );
            self.module.add_function("fread", fn_type, None)
        }
    }

    fn get_or_create_fwrite(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("fwrite") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            // fwrite signature: (i8*, i64, i64, void*) -> i64
            let fn_type = i64_type.fn_type(
                &[
                    i8ptr.into(),
                    i64_type.into(),
                    i64_type.into(),
                    void_ptr.into(),
                ],
                false,
            );
            self.module.add_function("fwrite", fn_type, None)
        }
    }

    fn get_or_create_fclose(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("fclose") {
            f
        } else {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            // fclose signature: (void*) -> i32
            let fn_type = self.context.i32_type().fn_type(&[void_ptr.into()], false);
            self.module.add_function("fclose", fn_type, None)
        }
    }

    fn get_or_create_sprintf(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("sprintf") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // sprintf signature: (i8*, i8*, ...) -> i32
            let fn_type = self
                .context
                .i32_type()
                .fn_type(&[i8ptr.into(), i8ptr.into()], true);
            self.module.add_function("sprintf", fn_type, None)
        }
    }

    fn get_or_create_printf(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("printf") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = self.context.i32_type().fn_type(&[i8ptr.into()], true);
            self.module.add_function("printf", fn_type, None)
        }
    }

    fn get_or_create_free(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("free") {
            f
        } else {
            // Correct C signature: void free(void*)
            let void_ty = self.context.void_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = void_ty.fn_type(&[void_ptr.into()], false);
            self.module.add_function("free", fn_type, None)
        }
    }

    fn expect_bool_value(&self, value: BasicValueEnum<'ctx>, context: &str) -> IntValue<'ctx> {
        if let BasicValueEnum::IntValue(int_val) = value {
            if int_val.get_type() == self.context.bool_type() {
                return int_val;
            }
        }
        panic!("Expected boolean value for {context}, found {:?}", value);
    }

    fn build_logical_binop(
        &self,
        left: &Expr,
        right: &Expr,
        op: &BinOp,
    ) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        let lhs_val = self.compile_expr(left)?;
        let lhs_bool = self.expect_bool_value(lhs_val, "logical lhs");

        let current_block = self
            .builder
            .get_insert_block()
            .expect("Logical operator must be inside a block");
        let parent_fn = current_block
            .get_parent()
            .expect("Logical operator must be inside a function");

        let rhs_block = self.context.append_basic_block(parent_fn, "logic_rhs");
        let end_block = self.context.append_basic_block(parent_fn, "logic_end");

        let bool_ty = self.context.bool_type();
        let true_const = bool_ty.const_int(1, false);
        let false_const = bool_ty.const_int(0, false);

        match op {
            BinOp::And => {
                self.builder
                    .build_conditional_branch(lhs_bool, rhs_block, end_block)?;
                self.builder.position_at_end(rhs_block);
                let rhs_val = self.compile_expr(right)?;
                let rhs_bool = self.expect_bool_value(rhs_val, "logical rhs");
                self.builder.build_unconditional_branch(end_block)?;
                let rhs_eval_block = self.builder.get_insert_block().unwrap();
                self.builder.position_at_end(end_block);
                let phi = self.builder.build_phi(bool_ty, "andtmp")?;
                phi.add_incoming(&[(&rhs_bool, rhs_eval_block), (&false_const, current_block)]);
                Ok(phi.as_basic_value())
            }
            BinOp::Or => {
                self.builder
                    .build_conditional_branch(lhs_bool, end_block, rhs_block)?;
                self.builder.position_at_end(rhs_block);
                let rhs_val = self.compile_expr(right)?;
                let rhs_bool = self.expect_bool_value(rhs_val, "logical rhs");
                self.builder.build_unconditional_branch(end_block)?;
                let rhs_eval_block = self.builder.get_insert_block().unwrap();
                self.builder.position_at_end(end_block);
                let phi = self.builder.build_phi(bool_ty, "ortmp")?;
                phi.add_incoming(&[(&true_const, current_block), (&rhs_bool, rhs_eval_block)]);
                Ok(phi.as_basic_value())
            }
            _ => unreachable!(),
        }
    }

    fn compile_expr(&self, expr: &Expr) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        match expr {
            Expr::Variable( var_name) => {
                let ptr = *self.vars.borrow().get(var_name).unwrap_or_else(||panic!("{var_name}"));
                let ty = *self.var_types.borrow().get(var_name).unwrap();
                let loaded = self.builder.build_load(ty, ptr, var_name)?;
                 Ok(loaded)
            }

            Expr::Get(ex, prop)if   matches!(*ex.clone(), Expr::Variable(i) if matches!(self.pctx.borrow().types.get(&i), Some(Custype::Enum(_)))) =>{
                let Expr::Variable(ref i) = **ex else {panic!()};
                let binding = self.pctx.borrow();
                let Custype::Enum(inna) = binding.types.get(i).unwrap() else {panic!()};
                let mut item = None;

                for (i, thing) in inna.iter().enumerate() {
                    if thing == prop {
                        item = Some(i);
                    }
                }

                let Some(index) = item else {
                    eprintln!("Could not find enum variant {prop} on enum {i}");
                    std::process::exit(70);
                };

                Ok(self.context.i64_type().const_int(index as u64, false).as_basic_value_enum())
            }


            // Handle io.random() as a call: io.ran"dom() → random integer < 1
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "random") =>
            {
                // call rand()
                let rand_fn = self.get_or_create_rand();
                let raw_i32 = self
                    .builder
                    .build_call(rand_fn, &[], "rand_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_int_value();

                // convert rand's i32 to f64
                let raw_f64 = self.builder.build_signed_int_to_float(
                    raw_i32,
                    self.context.f64_type(),
                    "rand_f64",
                )?;

                // get RAND_MAX as f64
                let rand_max = self.context.f64_type().const_float(2147483647.0); // RAND_MAX on mac/linux

                // return rand_f64 / rand_max
                let result = self
                    .builder
                    .build_float_div(raw_f64, rand_max, "rand_div")?;
                 Ok(result.as_basic_value_enum())
            }

            // io.listen(port: Num, callback: Function)
            Expr::Call(callee, args)
                if (args.len() == 2)
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "listen") =>
            {
                let port_f = self.compile_expr(&args[0])?.into_float_value();
                let i32t = self.context.i32_type();
                let port_i = self
                    .builder
                    .build_float_to_signed_int(port_f, i32t, "port_i")?;

                // New two-argument version with callback
                let callback_ptr = match &args[1] {
                    Expr::Variable(fname) => {
                        let bo = self.pctx.borrow();
                        let func_na = bo.var_types.get(fname);
                        match func_na {
                            Some(f) => match f {
                                Type::Function(params, ret) if **ret == Type::WebReturn => {
                                    // Enforce a single Request parameter to match server callback ABI
                                    if params.len() != 1 {
                                        eprintln!(
                                            "io.listen callback must take exactly one parameter (req). Update your handler to 'fun(req: Request) {{ ... }}'."
                                        );
                                        std::process::exit(70);
                                    }
                                            let mut request_fields = HashMap::new();
        request_fields.insert("method".to_string(), Type::Str);
        request_fields.insert("path".to_string(), Type::Str);
        // Represent query and headers as strings (parsed, human-readable)
        request_fields.insert("query".to_string(), Type::Str);
        request_fields.insert("headers".to_string(), Type::Str);
        request_fields.insert("body".to_string(), Type::Option(Box::new(Type::Str)));
                                                            if params[0].1 != Type::Custom(Custype::Object(request_fields)) {
                                          eprintln!(
                                "Type error: io.listen callback must take exactly one parameter (req). Found {:?} Update your handler to 'fun(req: Request) {{ ... }}'.", params[0].1
                            );
                            std::process::exit(70);
                        }
                                }
                                Type::WebReturn => {}
                                l => {
                                    eprintln!(
                                        "Expected handler function for io.listen to return a web return, found {l:?}"
                                    );
                                    std::process::exit(70);
                                }
                            },
                            None => {
                                if let Err(e) = self.infer_expr_type(&args[1]) {
                                    eprintln!("{e}");
                                    std::process::exit(70);
                                }
                            }
                        }

                        if let Some(func) = self.module.get_function(fname) {
                            let fn_ptr_val = func.as_global_value().as_pointer_value();
                            self.builder.build_pointer_cast(
                                fn_ptr_val,
                                self.context.ptr_type(AddressSpace::default()),
                                "fn_ptr_cast",
                            )?
                        } else {
                            self.compile_expr(&args[1])?.into_pointer_value()
                        }
                    }
                    // Inline function passed directly: enforce it returns WebReturn
                    Expr::Function(params, ret_ty, body) => {
                        if !returns_on_all_paths(vec![*body.clone()]) {
                            eprintln!("Inline function does not return on all paths");
                            std::process::exit(70);
                        }
                        if *ret_ty != Type::WebReturn {
                            eprintln!(
                                "io.listen callback must return a web response (e.g., io.web().text(...)). Add an explicit 'return ...' in the handler."
                            );
                            std::process::exit(70);
                        }
                        if params.len() != 1 {
                            eprintln!(
                                "io.listen callback must take exactly one parameter (req). Update your handler to 'fun(req) {{ ... }}'."
                            );
                            std::process::exit(70);
                        }
                                let mut request_fields = HashMap::new();
        request_fields.insert("method".to_string(), Type::Str);
        request_fields.insert("path".to_string(), Type::Str);
        // Represent query and headers as strings (parsed, human-readable)
        request_fields.insert("query".to_string(), Type::Str);
        request_fields.insert("headers".to_string(), Type::Str);
        request_fields.insert("body".to_string(), Type::Option(Box::new(Type::Str)));
                         if params[0].1 != Type::Custom(Custype::Object(request_fields)) {
                                          eprintln!(
                                "Type error: io.listen callback must take exactly one parameter (req). Found {:?} Update your handler to 'fun(req: Request) {{ ... }}'.", params[0].1
                            );
                            std::process::exit(70);
                        }
                        self.compile_expr(&args[1])?.into_pointer_value()
                    }
                    _ => self.compile_expr(&args[1])?.into_pointer_value(),
                };

                let listen_cb = self.get_or_create_qs_listen_with_callback();
                self.builder.build_call(
                    listen_cb,
                    &[port_i.into(), callback_ptr.into()],
                    "qs_listen_cb_call",
                )?;

                return Ok(self
                    .context
                    .f64_type()
                    .const_float(0.0)
                    .as_basic_value_enum());
            }
            // io.web() - returns a web helper object
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "web") =>
            {
                let web_helper_fn = self.get_or_create_web_helper();
                let web_obj = self
                    .builder
                    .build_call(web_helper_fn, &[], "web_helper_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(web_obj);
            }
            // io.read(filename: Str) - reads file content as string (async by default)
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "read") =>
            {
                let filename_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                let read_file_fn = self.get_or_create_io_read_file();
                let result = self
                    .builder
                    .build_call(read_file_fn, &[filename_ptr.into()], "io_read_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // io.write(filename: Str, content: Str) - writes content to file (async by default)
            Expr::Call(callee, args)
                if args.len() == 2
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "write") =>
            {
                let filename_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                let content_ptr = self.compile_expr(&args[1])?.into_pointer_value();
                let write_file_fn = self.get_or_create_io_write_file();
                let result = self
                    .builder
                    .build_call(
                        write_file_fn,
                        &[filename_ptr.into(), content_ptr.into()],
                        "io_write_call",
                    )
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // web.text(content: Str), web.page(content: Str), web.file(name: Str), web.json(content: Str)
            // Guard by receiver type (web helper), not just method name
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(obj, method) if {
                        if let Ok(Type::Custom(Custype::Object(fields))) =
                            self.infer_expr_type(obj)
                        {
                            match method.as_str() {
                                "text" => matches!(fields.get("text"), Some(Type::Function(params, ret))
                                    if params == &vec![("content".into(), Type::Str)] && **ret == Type::WebReturn),
                                "page" => matches!(fields.get("page"), Some(Type::Function(params, ret))
                                    if params == &vec![("content".into(), Type::Str)] && **ret == Type::WebReturn),
                                "file" => matches!(fields.get("file"), Some(Type::Function(params, ret))
                                    if params == &vec![("name".into(), Type::Str)] && **ret == Type::WebReturn),
                                "json" => matches!(fields.get("json"), Some(Type::Function(params, ret))
                                    if params == &vec![("content".into(), Type::Str)] && **ret == Type::WebReturn),
                                _ => false,
                            }
                        } else {
                            false
                        }
                    }) =>
            {
                if let Expr::Get(_obj, method) = &**callee {
                    let arg_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                    let callee_fn = match method.as_str() {
                        "text" => Some(self.get_or_create_web_text()),
                        "page" => Some(self.get_or_create_web_page()),
                        "file" => Some(self.get_or_create_web_file()),
                        "json" => Some(self.get_or_create_web_json()),
                        _ => None,
                    };
                    if let Some(f) = callee_fn {
                        let result = self
                            .builder
                            .build_call(f, &[arg_ptr.into()], "web_call")
                            .unwrap()
                            .try_as_basic_value()
                            .left()
                            .unwrap();
                        return Ok(result);
                    }
                    unreachable!("guard ensures known method");
                }
                unreachable!("guard ensures Expr::Get");
            }

            // Fallback: allow calling web helper methods by method name when
            // static type inference doesn't recognize the variable as the web helper.
            // This prevents panics like: Get(Variable("skib"), "file") when `skib = io.web()`.
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(_obj, method) if matches!(method.as_str(), "text" | "page" | "file" | "json")) =>
            {
                if let Expr::Get(_obj, method) = &**callee {
                    let arg_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                    let callee_fn = match method.as_str() {
                        "text" => Some(self.get_or_create_web_text()),
                        "page" => Some(self.get_or_create_web_page()),
                        "file" => Some(self.get_or_create_web_file()),
                        "json" => Some(self.get_or_create_web_json()),
                        _ => None,
                    };
                    if let Some(f) = callee_fn {
                        let result = self
                            .builder
                            .build_call(f, &[arg_ptr.into()], "web_call_fallback")
                            .unwrap()
                            .try_as_basic_value()
                            .left()
                            .unwrap();
                        return Ok(result);
                    } else {
                        unreachable!("matched known web method name");
                    }
                } else {
                    unreachable!("guard ensures Expr::Get");
                }
                // If it's not one of the known methods, let later arms handle it.
            }
            // web.redirect(location: Str, permanent: Bool)
            // Guard by receiver type (web helper), not just method name
            Expr::Call(callee, args)
                if args.len() == 2
                    && matches!(&**callee, Expr::Get(obj, method) if method == "redirect" && {
                        if let Ok(Type::Custom(Custype::Object(fields))) =
                            self.infer_expr_type(obj)
                        {
                            matches!(fields.get("redirect"), Some(Type::Function(params, ret))
                                if params == &vec![("location".into(), Type::Str), ("permanent".into(), Type::Bool)]
                                    && **ret == Type::WebReturn)
                        } else {
                            false
                        }
                    }) =>
            {
                let location_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                let permanent_bool = self.compile_expr(&args[1])?.into_int_value();
                let web_redirect_fn = self.get_or_create_web_redirect();
                let result = self
                    .builder
                    .build_call(
                        web_redirect_fn,
                        &[location_ptr.into(), permanent_bool.into()],
                        "web_redirect_call",
                    )
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            Expr::Call(callee, args)
                // web.error.text(status: Num, content: Str) and web.error.page(...), web.error.file(status: Num, name: Str)
                // Guard by receiver type shape, not only method names
                if args.len() == 2
                    && matches!(&**callee, Expr::Get(obj, method) if {
                        if let Expr::Get(inner_obj, prop) = &**obj {
                            if prop != "error" { false } else {
                                if let Ok(Type::Custom(Custype::Object(fields))) =
                                    self.infer_expr_type(inner_obj)
                                {
                                    if let Some(Type::Custom(Custype::Object(efields))) = fields.get("error") {
                                        match method.as_str() {
                                            "text" => matches!(efields.get("text"), Some(Type::Function(params, ret))
                                                if params == &vec![("status".into(), Type::Num), ("content".into(), Type::Str)] && **ret == Type::WebReturn),
                                            "page" => matches!(efields.get("page"), Some(Type::Function(params, ret))
                                                if params == &vec![("status".into(), Type::Num), ("content".into(), Type::Str)] && **ret == Type::WebReturn),
                                            "file" => matches!(efields.get("file"), Some(Type::Function(params, ret))
                                                if params == &vec![("status".into(), Type::Num), ("name".into(), Type::Str)] && **ret == Type::WebReturn),
                                            _ => false,
                                        }
                                    } else { false }
                                } else { false }
                            }
                        } else { false }
                    }) =>
            {
                if let Expr::Get(_obj, method) = &**callee {
                    let status_f = self.compile_expr(&args[0])?.into_float_value();
                    let i32t = self.context.i32_type();
                    let status_i = self
                        .builder
                        .build_float_to_signed_int(status_f, i32t, "status_i")?;
                    let content_ptr = self.compile_expr(&args[1])?.into_pointer_value();
                    let web_error_fn = match method.as_str() {
                        "text" => Some(self.get_or_create_web_error_text()),
                        "page" => Some(self.get_or_create_web_error_page()),
                        // "file" could be added here when implemented
                        _ => None,
                    };
                    if let Some(f) = web_error_fn {
                        let result = self
                            .builder
                            .build_call(
                                f,
                                &[status_i.into(), content_ptr.into()],
                                "web_error_call",
                            )
                            .unwrap()
                            .try_as_basic_value()
                            .left()
                            .unwrap();
                        return Ok(result);
                    }
                }
                unreachable!("guard ensures web.error method");
            }
            Expr::Call(callee, args)
                if args.len() <= 1
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "input") =>
            {
                // Read a line from stdin
                let malloc_fn = self.get_or_create_malloc();
                let fgets_fn = self.get_or_create_fgets();
                let stdin_fn = self.get_or_create_get_stdin();
                let strlen_fn = self.get_or_create_strlen();

                // If there's an argument, print it as a prompt
                if !args.is_empty() {
                    let prompt = self.compile_expr(&args[0])?;
                    let printf_fn = self.get_or_create_printf();
                    self.builder
                        .build_call(printf_fn, &[prompt.into()], "prompt_print")?;
                }

                // Allocate buffer for input (256 bytes should be enough for most inputs)
                let buffer_size = self.context.i64_type().const_int(256, false);
                let buffer =
                    self.builder
                        .build_call(malloc_fn, &[buffer_size.into()], "input_buffer")?;
                let buffer_ptr = buffer
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();

                // Get stdin file pointer
                let stdin_ptr = self.builder.build_call(stdin_fn, &[], "stdin_ptr")?;
                let stdin_file = stdin_ptr
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();

                // Read line from stdin using fgets
                let size_i32 = self.context.i32_type().const_int(256, false);
                let _result = self.builder.build_call(
                    fgets_fn,
                    &[buffer_ptr.into(), size_i32.into(), stdin_file.into()],
                    "fgets_call",
                )?;

                // Remove trailing newline if present
                let len_call =
                    self.builder
                        .build_call(strlen_fn, &[buffer_ptr.into()], "input_len")?;
                let len = len_call
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_int_value();

                // Check if length > 0 and last char is newline
                let zero = self.context.i64_type().const_zero();
                let one = self.context.i64_type().const_int(1, false);
                let has_content = self.builder.build_int_compare(
                    inkwell::IntPredicate::UGT,
                    len,
                    zero,
                    "has_content",
                )?;

                // Get pointer to last character
                let last_char_idx = self.builder.build_int_sub(len, one, "last_idx")?;
                let last_char_ptr = unsafe {
                    self.builder.build_gep(
                        self.context.i8_type(),
                        buffer_ptr,
                        &[last_char_idx],
                        "last_char_ptr",
                    )?
                };

                // Load last character
                let last_char =
                    self.builder
                        .build_load(self.context.i8_type(), last_char_ptr, "last_char")?;

                // Check if it's a newline (ASCII 10)
                let newline = self.context.i8_type().const_int(10, false);
                let is_newline = self.builder.build_int_compare(
                    inkwell::IntPredicate::EQ,
                    last_char.into_int_value(),
                    newline,
                    "is_newline",
                )?;

                // If it's a newline, replace it with null terminator
                let should_remove =
                    self.builder
                        .build_and(has_content, is_newline, "should_remove")?;
                let null_char = self.context.i8_type().const_zero();

                // Conditionally store null character
                let current_bb = self.builder.get_insert_block().unwrap();
                let function = current_bb.get_parent().unwrap();
                let then_bb = self.context.append_basic_block(function, "remove_newline");
                let cont_bb = self.context.append_basic_block(function, "input_done");

                self.builder
                    .build_conditional_branch(should_remove, then_bb, cont_bb)?;

                // Then block: remove newline
                self.builder.position_at_end(then_bb);
                self.builder.build_store(last_char_ptr, null_char)?;
                self.builder.build_unconditional_branch(cont_bb)?;

                // Continue block
                self.builder.position_at_end(cont_bb);

                Ok(buffer_ptr.as_basic_value_enum())
            }
            Expr::Call(callee, args)
                if !args.is_empty()
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "read") =>
            {
                let filename = self.compile_expr(&args[0])?;
                let read_mode = self
                    .builder
                    .build_global_string_ptr("r\0", "read_mode")
                    .unwrap();
                let fopen_fn = self.get_or_create_fopen();
                let file_ptr = self
                    .builder
                    .build_call(
                        fopen_fn,
                        &[filename.into(), read_mode.as_pointer_value().into()],
                        "fopen_call",
                    )
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();

                let buffer_size = self.context.i64_type().const_int(1024, false);
                let buffer = self
                    .builder
                    .build_alloca(self.context.i8_type().array_type(1024), "read_buffer")
                    .unwrap();
                let fread_fn = self.get_or_create_fread();
                self.builder
                    .build_call(
                        fread_fn,
                        &[
                            buffer.into(),
                            buffer_size.into(),
                            self.context.i64_type().const_int(1, false).into(),
                            file_ptr.into(),
                        ],
                        "fread_call",
                    )
                    .unwrap();
 
                let fclose_fn = self.get_or_create_fclose();
                self.builder
                    .build_call(fclose_fn, &[file_ptr.into()], "fclose_call")
                    .unwrap();

                Ok(buffer.as_basic_value_enum())
            }
            Expr::Call(callee, args)
                if args.len() == 2
                    && matches!(&**callee, Expr::Get(obj, method) if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "write") =>
            {
                let filename = self.compile_expr(&args[0])?;
                let content = self.compile_expr(&args[1])?;
                let write_mode = self
                    .builder
                    .build_global_string_ptr("w\0", "write_mode")
                    .unwrap();
                let fopen_fn = self.get_or_create_fopen();
                let file_ptr = self
                    .builder
                    .build_call(
                        fopen_fn,
                        &[filename.into(), write_mode.as_pointer_value().into()],
                        "fopen_call",
                    )
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();

                let content_ptr = content.into_pointer_value();
                let strlen_fn = self.get_or_create_strlen();
                let len = self
                    .builder
                    .build_call(strlen_fn, &[content_ptr.into()], "strlen_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_int_value();

                let fwrite_fn = self.get_or_create_fwrite();
                self.builder
                    .build_call(
                        fwrite_fn,
                        &[
                            content_ptr.into(),
                            len.into(),
                            self.context.i64_type().const_int(1, false).into(),
                            file_ptr.into(),
                        ],
                        "fwrite_call",
                    )
                    .unwrap();

                let fclose_fn = self.get_or_create_fclose();
                self.builder
                    .build_call(fclose_fn, &[file_ptr.into()], "fclose_call")
                    .unwrap();

                Ok(self
                    .context
                    .i64_type()
                    .const_int(0, false)
                    .as_basic_value_enum())
            }
            Expr::Get(obj, method) if method == "str" => {
                let compiled_obj = self.compile_expr(obj)?;
                if let BasicValueEnum::FloatValue(float_val) = compiled_obj {
                    let sprintf_fn = self.get_or_create_sprintf();
                    let malloc_fn = self.get_or_create_malloc();

                    // Allocate buffer for string (e.g., 64 bytes for float string representation)
                    let buffer_size = self.context.i64_type().const_int(64, false);
                    let buffer_ptr = self.builder.build_call(
                        malloc_fn,
                        &[buffer_size.into()],
                        "str_buf_malloc",
                    )?;
                    let buffer_ptr = buffer_ptr
                        .try_as_basic_value()
                        .left()
                        .unwrap()
                        .into_pointer_value();

                    // Format string: "%f\0"
                    let format_str = self
                        .builder
                        .build_global_string_ptr("%f\0", "float_fmt_str")
                        .unwrap();

                    // Call sprintf
                    self.builder.build_call(
                        sprintf_fn,
                        &[
                            buffer_ptr.into(),
                            format_str.as_pointer_value().into(),
                            float_val.into(),
                        ],
                        "sprintf_call",
                    )?;

                    Ok(buffer_ptr.as_basic_value_enum())
                } else {
                    panic!("Unsupported .str() call on non-numeric type");
                }
            }
            Expr::Literal(Value::Num(n)) => {
                // Cast f64 to u64 for integer literal
                Ok(self
                    .context
                    .f64_type()
                    .const_float(*n)
                    .as_basic_value_enum())
            }
            Expr::Literal(Value::Bool(b)) => {
                let val = if *b { 1 } else { 0 };
                Ok(self
                    .context
                    .bool_type()
                    .const_int(val, false)
                    .as_basic_value_enum())
            }
            Expr::Literal(Value::Nil) => {
                // Represent nil as the C-string "nil"
                let gs = self
                    .builder
                    .build_global_string_ptr("nil\0", "nil_literal")
                    .unwrap();
                //Ok(gs.as_pointer_value().as_basic_value_enum());
                Ok(BasicValueEnum::PointerValue(
                    self.context.ptr_type(AddressSpace::default()).const_null(),
                ))
            }
            Expr::Binary(left, op, right) => {
                if matches!(op, BinOp::And | BinOp::Or) {
                    return self.build_logical_binop(left, right, op);
                }

                // Compile both sides
                let lval = match self.compile_expr(left)? {
                    BasicValueEnum::IntValue(i) => self
                        .builder
                        .build_signed_int_to_float(i, self.context.f64_type(), "number_value")?
                        .as_basic_value_enum(),
                    o => o,
                };
                let rval = match self.compile_expr(right)? {
                    BasicValueEnum::IntValue(i) => self
                        .builder
                        .build_signed_int_to_float(i, self.context.f64_type(), "number_value")?
                        .as_basic_value_enum(),
                    o => o,
                };

                match (lval, rval) {
                    (BasicValueEnum::FloatValue(li), BasicValueEnum::FloatValue(ri)) => {
                        // Integer operations
                        Ok(match op {
                            BinOp::Plus => self.builder.build_float_add(li, ri, "addtmp")?.into(),
                            BinOp::Minus => self.builder.build_float_sub(li, ri, "subtmp")?.into(),
                            BinOp::Mult => self.builder.build_float_mul(li, ri, "multmp")?.into(),
                            BinOp::Div => self.builder.build_float_div(li, ri, "divtmp")?.into(),
                            BinOp::EqEq => self
                                .builder
                                .build_float_compare(FloatPredicate::OEQ, li, ri, "eqtmp")?
                                .into(),
                            BinOp::NotEq => self
                                .builder
                                .build_float_compare(FloatPredicate::ONE, li, ri, "netmp")?
                                .into(),
                            BinOp::Less => self
                                .builder
                                .build_float_compare(FloatPredicate::OLT, li, ri, "lttmp")?
                                .into(),
                            BinOp::LessEqual => self
                                .builder
                                .build_float_compare(FloatPredicate::OLE, li, ri, "letmp")?
                                .into(),
                            BinOp::Greater => self
                                .builder
                                .build_float_compare(FloatPredicate::OGT, li, ri, "gttmp")?
                                .into(),
                            BinOp::GreaterEqual => self
                                .builder
                                .build_float_compare(FloatPredicate::OGE, li, ri, "getmp")?
                                .into(),
                            _ => unreachable!("Unhandled binary operator {op:?} for floats"),
                        })
                    }
                    (BasicValueEnum::PointerValue(lp), BasicValueEnum::PointerValue(rp)) => {
                        // String case: call strcmp and compare its result or do concatenation
                        match op {
                            BinOp::Plus => {
                                // Simple but efficient string concatenation
                                let strlen_fn = self.get_or_create_strlen();
                                let malloc_fn = self.get_or_create_malloc();
                                let strcpy_fn = self.get_or_create_strcpy();
                                let strcat_fn = self.get_or_create_strcat_c();

                                // Get lengths
                                let len1_call =
                                    self.builder.build_call(strlen_fn, &[lp.into()], "len1")?;
                                let len1 = len1_call
                                    .try_as_basic_value()
                                    .left()
                                    .unwrap()
                                    .into_int_value();
                                let len2_call =
                                    self.builder.build_call(strlen_fn, &[rp.into()], "len2")?;
                                let len2 = len2_call
                                    .try_as_basic_value()
                                    .left()
                                    .unwrap()
                                    .into_int_value();

                                // total_len = len1 + len2 + 1
                                let sum = self.builder.build_int_add(len1, len2, "len_sum")?;
                                let one = self.context.i64_type().const_int(1, false);
                                let total_len =
                                    self.builder.build_int_add(sum, one, "total_len")?;

                                // malloc(buffer)
                                let buf_ptr = self.builder.build_call(
                                    malloc_fn,
                                    &[total_len.into()],
                                    "malloc_buf",
                                )?;
                                let buf_ptr = buf_ptr
                                    .try_as_basic_value()
                                    .left()
                                    .unwrap()
                                    .into_pointer_value();

                                // strcpy(buf, lp)
                                self.builder.build_call(
                                    strcpy_fn,
                                    &[buf_ptr.into(), lp.into()],
                                    "strcpy_call",
                                )?;
                                // strcat(buf, rp)
                                self.builder.build_call(
                                    strcat_fn,
                                    &[buf_ptr.into(), rp.into()],
                                    "strcat_call",
                                )?;

                                Ok(buf_ptr.as_basic_value_enum())
                            }
                            // String comparison cases
                            _ => {
                                let strcmp_fn = self.get_or_create_strcmp();
                                let cmp_call = self.builder.build_call(
                                    strcmp_fn,
                                    &[lp.into(), rp.into()],
                                    "strcmp_call",
                                )?;
                                let cmp = cmp_call
                                    .try_as_basic_value()
                                    .left()
                                    .unwrap()
                                    .into_int_value();
                                // Zero constant for strcmp result
                                let zero = self.context.i32_type().const_int(0, false);
                                Ok(match op {
                                    BinOp::EqEq => self
                                        .builder
                                        .build_int_compare(IntPredicate::EQ, cmp, zero, "streq")?
                                        .into(),
                                    BinOp::NotEq => self
                                        .builder
                                        .build_int_compare(IntPredicate::NE, cmp, zero, "strneq")?
                                        .into(),
                                    BinOp::Less => self
                                        .builder
                                        .build_int_compare(IntPredicate::SLT, cmp, zero, "strlt")?
                                        .into(),
                                    BinOp::LessEqual => self
                                        .builder
                                        .build_int_compare(IntPredicate::SLE, cmp, zero, "strle")?
                                        .into(),
                                    BinOp::Greater => self
                                        .builder
                                        .build_int_compare(IntPredicate::SGT, cmp, zero, "strgt")?
                                        .into(),
                                    BinOp::GreaterEqual => self
                                        .builder
                                        .build_int_compare(IntPredicate::SGE, cmp, zero, "strge")?
                                        .into(),
                                    _ => {
                                        panic!("Unsupported operator for string comparison: {op:?}")
                                    }
                                })
                            }
                        }
                    }
                    _ => panic!("Type mismatch in binary expression: {lval} vs {rval}",),
                }
            }

            Expr::Literal(Value::Str(s)) => {
                // 1) stick a C
                // -string into the module
                let gs = self
                    .builder
                    .build_global_string_ptr(&format!("{s}\0"), "str_literal")
                    .unwrap();
                // 2) cast the pointer to an i64
                Ok(gs.as_basic_value_enum())
            }
            Expr::Object(type_name, fields) => {
                // Allocate storage for a flat object
                let slot_ty = self.context.ptr_type(AddressSpace::default());
                let slot_bytes = self
                    .context
                    .i64_type()
                    .const_int(mem::size_of::<u64>() as u64, false);
                let count = self
                    .context
                    .i64_type()
                    .const_int(fields.len() as u64, false);
                let total_bytes = self
                    .builder
                    .build_int_mul(slot_bytes, count, "obj_size")
                    .unwrap();
                // Call malloc
                let malloc_fn = self.get_or_create_malloc();
                let raw_ptr = self
                    .builder
                    .build_call(malloc_fn, &[total_bytes.into()], "malloc_obj")
                    .unwrap();
                let raw_ptr = raw_ptr
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();
                let obj_ptr = self
                    .builder
                    .build_pointer_cast(raw_ptr, slot_ty, "obj_ptr")?;
                // Store each field at its index based on the declared type order
                let binding = self.pctx.borrow();
                let Custype::Object(type_fields) = binding.types.get(type_name).unwrap() else {
                    panic!()
                };
                for (idx, field_name) in type_fields.keys().enumerate() {
                    let expr = &fields[field_name];
                    let val = self.compile_expr(expr)?;
                    let idx_const = self.context.i64_type().const_int(idx as u64, false);
                    let field_ptr = unsafe {
                        // Treat each slot as an i64-sized cell for indexing
                        self.builder
                            .build_in_bounds_gep(
                                self.context.i64_type(),
                                obj_ptr,
                                &[idx_const],
                                &format!("field_{field_name}"),
                            )
                            .unwrap()
                    };
                    let _ = self.builder.build_store(field_ptr, val);
                }
                Ok(obj_ptr.as_basic_value_enum())
            }
            Expr::Get(obj_expr, prop) => {
                // Module constant access: module_name.CONST
                if let Expr::Variable(var_name) = &**obj_expr {
                    if let Some(minfo) = self.pctx.borrow().modules.get(var_name) {
                        if let Some(c_expr) = minfo.constants.get(prop) {
                            // Compile the constant expression (literal only)
                            return self.compile_expr(c_expr);
                        }
                    }
                }

                // io.range – create a fresh RangeBuilder
                if matches!(&**obj_expr, Expr::Variable(name) if name == "io")
                    && prop == "range"
                {
                    let ctor = self.get_or_create_range_builder();
                    let builder = self
                        .builder
                        .build_call(ctor, &[], "create_range_builder")?
                        .try_as_basic_value()
                        .left()
                        .unwrap();
                    return Ok(builder);
                }

                // Special case for Request object property access
                if let Expr::Variable(var_name) = &**obj_expr {
                    let binding = self.pctx.borrow();
                    if let Some(Type::Custom(Custype::Object(type_map))) =
                        binding.var_types.get(var_name)
                    {
                        // Check if this is a Request object by looking for Request fields
                        if type_map.contains_key("method") && type_map.contains_key("path") {
                            // This is a Request object - use the actual Request object pointer
                            let request_ptr = self.compile_expr(obj_expr)?.into_pointer_value();
                            match prop.as_str() {
                                "method" => {
                                    let get_method_fn = self.get_or_create_get_request_method();
                                    let result = self.builder.build_call(
                                        get_method_fn,
                                        &[request_ptr.into()],
                                        "get_method_call",
                                    )?;
                                    return Ok(result.try_as_basic_value().left().unwrap());
                                }
                                "path" => {
                                    let get_path_fn = self.get_or_create_get_request_path();
                                    let result = self.builder.build_call(
                                        get_path_fn,
                                        &[request_ptr.into()],
                                        "get_path_call",
                                    )?;
                                    return Ok(result.try_as_basic_value().left().unwrap());
                                }
                                "body" => {
                                    let get_body_fn = self.get_or_create_get_request_body();
                                    let result = self.builder.build_call(
                                        get_body_fn,
                                        &[request_ptr.into()],
                                        "get_body_call",
                                    )?;
                                    return Ok(result.try_as_basic_value().left().unwrap());
                                }
                                "query" => {
                                    let get_query_fn = self.get_or_create_get_request_query();
                                    let result = self.builder.build_call(
                                        get_query_fn,
                                        &[request_ptr.into()],
                                        "get_query_call",
                                    )?;
                                    return Ok(result.try_as_basic_value().left().unwrap());
                                }
                                "headers" => {
                                    let get_headers_fn = self.get_or_create_get_request_headers();
                                    let result = self.builder.build_call(
                                        get_headers_fn,
                                        &[request_ptr.into()],
                                        "get_headers_call",
                                    )?;
                                    return Ok(result.try_as_basic_value().left().unwrap());
                                }
                                _ => {
                                    // Fall through to regular property access
                                }
                            }
                        }
                        // Check if this is a Web helper object
                        else if var_name == "web" {
                            // Return a function pointer for web methods
                            // This will be handled in Call expressions
                            let web_ptr = self.compile_expr(obj_expr)?.into_pointer_value();
                            return Ok(web_ptr.as_basic_value_enum());
                        }
                    }
                }

                // Regular property access for other objects
                // Compile the base object pointer
                let base_val = self.compile_expr(obj_expr)?;
                let obj_ptr = base_val.into_pointer_value();
                // Determine the object's declared type using type inference so property access works
                // on expressions like list indexing, not just named variables.
                let inferred_type = self
                    .infer_expr_type(obj_expr)
                    .expect("Unable to infer type for property access");
                let custom_type = match inferred_type {
                    Type::Custom(ref map) => map,
                    Type::Option(inner) => &match *inner {
                        Type::Custom(ref map) => map.clone(),
                        other => panic!(
                            "Property access on option whose inner type {other:?} is not an object"
                        ),
                    },
                    other => {
                        panic!("Property access on non-object expression: {other:?}")
                    }
                };
                let type_name = self
                    .pctx
                    .borrow()
                    .types
                    .iter()
                    .find(|(_, def)| def == &custom_type)
                    .map(|(k, _)| k.clone())
                    .unwrap();
                let Custype::Object(field_defs) = &self.pctx.borrow().types[&type_name] else {
                    panic!()
                };
                // Find the index of this property
                let index = field_defs.keys().position(|k| k == prop).unwrap() as u64;
                let idx_const = self.context.i64_type().const_int(index, false);
                let slot_ty = self.context.ptr_type(AddressSpace::default());
                // Compute address and load
                // Compute the address of the field
                let field_ptr = unsafe {
                    // Index by 8-byte slots (i64) for opaque pointer arrays
                    self.builder
                        .build_in_bounds_gep(
                            self.context.i64_type(),
                            obj_ptr,
                            &[idx_const],
                            &format!("load_{}", prop),
                        )
                        .unwrap()
                };
                // Determine the field’s QuickLang type
                let binding = self.pctx.borrow();
                let Custype::Object(binding) = binding.types[&type_name].clone() else {
                    panic!()
                };
                let field_ty = binding[prop].clone();
                // Pick the right LLVM type
                let elem_basic = match field_ty.unwrap() {
                    Type::Str | Type::List(_) => self
                        .context
                        .ptr_type(AddressSpace::default())
                        .as_basic_type_enum(),
                    Type::Num => self.context.f64_type().as_basic_type_enum(),
                    Type::Bool => self.context.bool_type().as_basic_type_enum(),
                    other => panic!("Unsupported field type {other:?}"),
                };
                // Load with the correct type
                let loaded = self
                    .builder
                    .build_load(elem_basic, field_ptr, prop)
                    .unwrap();
                Ok(loaded)
            }
            Expr::Call(callee, args) => {
                // Special case: module_name.func(...)
                if let Expr::Get(obj, method) = &**callee {
                    if let Expr::Variable(modname) = &**obj {
                        if self.pctx.borrow().modules.contains_key(modname) {
                            let compiled_args: Vec<BasicMetadataValueEnum> = args
                                .iter()
                                .map(|a| self.compile_expr(a).unwrap().into())
                                .collect();
                            let ns = format!("{}__{}", modname, method);
                            let function = self
                                .module
                                .get_function(&ns)
                                .unwrap_or_else(|| panic!(
                                    "Undefined module function `{}` in `{}`",
                                    method, modname
                                ));
                            let call_site = self
                                .builder
                                .build_call(function, &compiled_args, &format!("call_{}", ns))
                                .unwrap();
                            if let Some(rv) = call_site.try_as_basic_value().left() {
                                return Ok(rv.as_basic_value_enum());
                            } else {
                                return Ok(self
                                    .context
                                    .i64_type()
                                    .const_int(0, false)
                                    .as_basic_value_enum());
                            }
                        }
                    }
                }
                // Compile the function or method being called
                match &**callee {
                    // Obj.new()
                    Expr::Get(inner, method)
                        if method == "new"
                            && matches!(&**inner, Expr::Variable(n) if n == "Obj")
                            && args.is_empty() =>
                    {
                        let fnv = self.get_or_create_qs_obj_new();
                        let call = self.builder.build_call(fnv, &[], "obj_new").unwrap();
                        Ok(call.try_as_basic_value().left().unwrap().as_basic_value_enum())
                    }

                    // RangeBuilder builder methods: `.to()`, `.from()`, `.step()`
                    Expr::Get(receiver, method)
                        if args.len() == 1
                            && matches!(
                                self.infer_expr_type(receiver),
                                Ok(Type::RangeBuilder)
                            )
                            && matches!(method.as_str(), "to" | "from" | "step") =>
                    {
                        let builder_val = self.compile_expr(receiver)?;
                        let builder_ptr = match builder_val {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(
                                "RangeBuilder methods expect a pointer receiver, got {other:?}"
                            ),
                        };

                        let raw_arg = self.compile_expr(&args[0])?;
                        let f64_ty = self.context.f64_type();
                        let arg_f64 = match raw_arg {
                            BasicValueEnum::FloatValue(f) => f,
                            BasicValueEnum::IntValue(i) => self
                                .builder
                                .build_signed_int_to_float(
                                    i,
                                    f64_ty,
                                    "range_arg_cast",
                                )?,
                            other => panic!(
                                "RangeBuilder setter expected numeric argument, got {other:?}"
                            ),
                        };

                        let setter = match method.as_str() {
                            "to" => self.get_or_create_range_builder_to(),
                            "from" => self.get_or_create_range_builder_from(),
                            "step" => self.get_or_create_range_builder_step(),
                            _ => unreachable!("guard ensures known method"),
                        };

                        let call = self.builder.build_call(
                            setter,
                            &[builder_ptr.into(), arg_f64.into()],
                            "range_builder_set",
                        )?;

                        Ok(call.try_as_basic_value().left().unwrap())
                    }

                    // obj.insert(key, val)
                    Expr::Get(obj, method)
                        if method == "insert"
                            && matches!(
                                self.infer_expr_type(obj),
                                Ok(Type::Kv(_))
                            ) =>
                    {
                        let map_ptr = self.compile_expr(obj)?;
                        let key = self.compile_expr(&args[0])?;
                        let raw_val = self.compile_expr(&args[1])?;

                        // Ensure value argument is an opaque pointer. If it's numeric/bool,
                        // convert to a freshly allocated string first.
                        let void_ptr_ty = self.context.ptr_type(AddressSpace::default());
                        let pointer_value = match raw_val {
                            BasicValueEnum::PointerValue(p) => {
                                if p.get_type() == void_ptr_ty {
                                    p
                                } else {
                                    self.builder
                                        .build_pointer_cast(
                                            p,
                                            void_ptr_ty,
                                            "obj_insert_cast_ptr",
                                        )
                                        .unwrap()
                                }
                            }
                            BasicValueEnum::FloatValue(fv) => {
                                // Allocate buffer and sprintf "%f"
                                let fmt = self
                                    .builder
                                    .build_global_string_ptr("%f\0", "fmt_insert_f")
                                    .unwrap();
                                let malloc_fn = self.get_or_create_malloc();
                                let size = self.context.i64_type().const_int(64, false);
                                let buf = self
                                    .builder
                                    .build_call(malloc_fn, &[size.into()], "malloc_fbuf")
                                    .unwrap()
                                    .try_as_basic_value()
                                    .left()
                                    .unwrap()
                                    .into_pointer_value();
                                let sprintf_fn = self.get_or_create_sprintf();
                                self.builder
                                    .build_call(
                                        sprintf_fn,
                                        &[buf.into(), fmt.as_pointer_value().into(), fv.into()],
                                        "sprintf_f",
                                    )
                                    .unwrap();
                                self
                                    .builder
                                    .build_pointer_cast(
                                        buf,
                                        void_ptr_ty,
                                        "obj_insert_float_ptr",
                                    )
                                    .unwrap()
                            }
                            BasicValueEnum::IntValue(iv) => {
                                // Treat 1-bit ints as bool; 8+/32/64 as integer via %ld
                                if iv.get_type().get_bit_width() == 1 {
                                    // Build pointers to "true" and "false"
                                    let t = self
                                        .builder
                                        .build_global_string_ptr("true\0", "bool_true")
                                        .unwrap()
                                        .as_pointer_value();
                                    let f = self
                                        .builder
                                        .build_global_string_ptr("false\0", "bool_false")
                                        .unwrap()
                                        .as_pointer_value();
                                    let sel = self
                                        .builder
                                        .build_select(iv, t, f, "bool_sel")
                                        .unwrap()
                                        .into_pointer_value();
                                    self
                                        .builder
                                        .build_pointer_cast(
                                            sel,
                                            void_ptr_ty,
                                            "obj_insert_bool_ptr",
                                        )
                                        .unwrap()
                                } else {
                                    // Generic integer: sprintf with "%ld"
                                    let fmt = self
                                        .builder
                                        .build_global_string_ptr("%ld\0", "fmt_insert_i")
                                        .unwrap();
                                    let malloc_fn = self.get_or_create_malloc();
                                    let size = self.context.i64_type().const_int(64, false);
                                    let buf = self
                                        .builder
                                        .build_call(malloc_fn, &[size.into()], "malloc_ibuf")
                                        .unwrap()
                                        .try_as_basic_value()
                                        .left()
                                        .unwrap()
                                        .into_pointer_value();
                                    let sprintf_fn = self.get_or_create_sprintf();
                                    self.builder
                                        .build_call(
                                            sprintf_fn,
                                            &[buf.into(), fmt.as_pointer_value().into(), iv.into()],
                                            "sprintf_i",
                                        )
                                        .unwrap();
                                    self
                                        .builder
                                        .build_pointer_cast(
                                            buf,
                                            void_ptr_ty,
                                            "obj_insert_int_ptr",
                                        )
                                        .unwrap()
                                }
                            }
                            other => panic!("Unsupported value type for Obj.insert: {:?}", other),
                        };

                        let val_as_ptr: BasicMetadataValueEnum = pointer_value.into();

                        let fnv = self.get_or_create_qs_obj_insert_str();
                        let _ = self
                            .builder
                            .build_call(
                                fnv,
                                &[map_ptr.into(), key.into(), val_as_ptr],
                                "obj_ins",
                            )
                            .unwrap();
                        // return 0.0 as Nil placeholder
                        Ok(self.context.f64_type().const_float(0.0).as_basic_value_enum())
                    }

                    // a = obj.get(key)
                    Expr::Get(obj, method)
                        if method == "get"
                            && matches!(
                                self.infer_expr_type(obj),
                                Ok(Type::Kv(_))
                            ) =>
                    {
                        let map_ptr = self.compile_expr(obj)?;
                        let key = self.compile_expr(&args[0])?;
                        let fnv = self.get_or_create_qs_obj_get_str();
                        let call = self
                            .builder
                            .build_call(fnv, &[map_ptr.into(), key.into()], "obj_get")
                            .unwrap();
                        Ok(call.try_as_basic_value().left().unwrap().as_basic_value_enum())
                    }
                    // 1) Direct function call: foo(arg1, arg2, ...)
                    Expr::Variable(name) => {
                        // If compiling inside a module, prefer namespaced function resolution
                        if let Some(cur_mod) = self.current_module.borrow().clone() {
                            let ns = format!("{}__{}", cur_mod, name);
                            if let Some(function) = self.module.get_function(&ns) {
                                let compiled_args: Vec<BasicMetadataValueEnum> = args
                                    .iter()
                                    .map(|a| self.compile_expr(a).unwrap().into())
                                    .collect();
                                let call_site = self
                                    .builder
                                    .build_call(function, &compiled_args, &format!("call_{}", ns))
                                    .unwrap();
                                if let Some(rv) = call_site.try_as_basic_value().left() {
                                    return Ok(rv.as_basic_value_enum());
                                } else {
                                    return Ok(self
                                        .context
                                        .i64_type()
                                        .const_int(0, false)
                                        .as_basic_value_enum());
                                }
                            }
                        }
                        // Look up the JIT-compiled function in the module
                        let function = self
                            .module
                            .get_function(name)
                            .unwrap_or_else(|| panic!("Undefined function `{}`", name));

                        // Compile each argument
                        let mut compiled_args = Vec::with_capacity(args.len());
                        for arg in args {
                            compiled_args.push(self.compile_expr(arg)?);
                        }

                        // Convert to metadata for build_call
                        let metadata_args: Vec<BasicMetadataValueEnum> =
                            compiled_args.iter().map(|v| (*v).into()).collect();

                        // Emit the call
                        let call_site = self
                            .builder
                            .build_call(function, &metadata_args, &format!("call_{}", name))
                            .unwrap();

                        // If it returns a value, pull it out; otherwise default to zero
                        if let Some(rv) = call_site.try_as_basic_value().left() {
                            Ok(rv.as_basic_value_enum())
                        } else {
                            Ok(self
                                .context
                                .i64_type()
                                .const_int(0, false)
                                .as_basic_value_enum())
                        }
                    }

                    // Method call `.str()` on numeric values
                    Expr::Get(obj, method)
                        if method == "str"
                            && self.expr_type_matches(obj, |t| matches!(t.unwrap(), Type::Num)) =>
                    {
                        // Ensure the object compiles to an integer before converting
                        let compiled_val = self.compile_expr(obj)?;
                        let num_val = match compiled_val {
                            BasicValueEnum::FloatValue(f) => f,
                            BasicValueEnum::IntValue(iv) => {
                                self.builder.build_signed_int_to_float(
                                    iv,
                                    self.context.f64_type(),
                                    "int_to_float",
                                )?
                            }
                            other => panic!(".str() called on non-numeric object: {:?}", other),
                        };
                        // Prepare a "%ld" format string
                        let fmt = self
                            .builder
                            .build_global_string_ptr("%f\0", "fmt_str")
                            .unwrap();
                        // Allocate a 32-byte buffer
                        let size = self.context.i64_type().const_int(128, false);
                        let malloc_fn = self.get_or_create_malloc();
                        let buf_ptr = self
                            .builder
                            .build_call(malloc_fn, &[size.into()], "malloc_buf")
                            .unwrap();
                        let buf_ptr = buf_ptr
                            .try_as_basic_value()
                            .left()
                            .unwrap()
                            .into_pointer_value();
                        // Call sprintf(buf, "%ld", num_val)
                        let sprintf_fn = self.get_or_create_sprintf();
                        self.builder.build_call(
                            sprintf_fn,
                            &[
                                buf_ptr.into(),
                                fmt.as_pointer_value().into(),
                                num_val.into(),
                            ],
                            "sprintf_call",
                        )?;
                        // Return the string pointer
                        Ok(buf_ptr.as_basic_value_enum())
                    }

                    // 2) Method call `.len()` on a pointer value (string or list)
                    Expr::Get(obj, method)
                        if method == "len"
                            && self.expr_type_matches(
                                obj,
                                |t| matches!(t.unwrap(), Type::List(_) | Type::Str),
                            ) =>
                    {
                        let obj_val = self.compile_expr(obj)?;
                        // Get the original type of the object from pctx
                        let obj_type = self
                            .infer_expr_type(obj)
                            .unwrap_or_else(|e| panic!("Type error: {e}"));

                        if let BasicValueEnum::PointerValue(ptr) = obj_val {
                            match obj_type {
                                Type::Str => {
                                    // For strings, call strlen
                                    let strlen_fn = self.get_or_create_strlen();
                                    let result = self.builder.build_call(
                                        strlen_fn,
                                        &[ptr.into()],
                                        "strlen_call",
                                    )?;
                                    let result = result
                                        .try_as_basic_value()
                                        .left()
                                        .unwrap()
                                        .into_int_value();
                                    Ok(result.as_basic_value_enum())
                                }
                                Type::List(_) => {
                                    // For lists, load length from the first element
                                    let i64_ty = self.context.f64_type();
                                    let len = self.builder.build_load(i64_ty, ptr, "len")?;
                                    Ok(len.as_basic_value_enum())
                                }
                                _ => panic!("Unsupported type for .len() call: {:?}", obj_type),
                            }
                        } else {
                            panic!("Unsupported type for .len() call");
                        }
                    }
                    Expr::Get(obj, method)
                        if method == "num"
                            && self
                                .infer_expr_type(obj)
                                .unwrap_or_else(|e| panic!("Type error: {e}"))
                                == Type::Str =>
                    {
                        let obj_val = match self.compile_expr(obj)? {
                            BasicValueEnum::PointerValue(p) => p,
                            _ => panic!(),
                        };

                        // Get the original type of the object from pctx
                        let atoi_fn = self.get_or_create_atoi();
                        let result =
                            self.builder
                                .build_call(atoi_fn, &[obj_val.into()], "atoi_call")?;
                        let result = self.builder.build_signed_int_to_float(
                            result.try_as_basic_value().left().unwrap().into_int_value(),
                            self.context.f64_type(),
                            "int_to_float",
                        )?;
                        Ok(result.as_basic_value_enum())
                    }

                    Expr::Get(obj, method)
                        if method == "contains"
                            && self
                                .infer_expr_type(obj)
                                .unwrap_or_else(|e| panic!("Type error: {e}"))
                                == Type::Str
                            && args.len() == 1 =>
                    {
                        let obj_val = match self.compile_expr(obj)? {
                            BasicValueEnum::PointerValue(p) => p,
                            _ => panic!(),
                        };

                        let find = self.compile_expr(&args[0])?;

                        // Get the original type of the object from pctx
                        let strstr_fn = self.get_or_create_strstr();
                        let result = self
                            .builder
                            .build_call(strstr_fn, &[obj_val.into(), find.into()], "strstr_call")?
                            .try_as_basic_value()
                            .unwrap_left();
                        let cond = match result {
                            BasicValueEnum::PointerValue(ptr) => {
                                let null_ptr =
                                    self.context.ptr_type(AddressSpace::default()).const_null();
                                self.builder.build_int_compare(
                                    IntPredicate::NE,
                                    ptr,
                                    null_ptr,
                                    "neq_nil",
                                )
                            }
                            BasicValueEnum::FloatValue(iv) => {
                                let zero = self.context.f64_type().const_float(0.0);
                                self.builder.build_float_compare(
                                    FloatPredicate::ONE,
                                    iv,
                                    zero,
                                    "neq_nil",
                                )
                            }
                            BasicValueEnum::IntValue(i) => {
                                let zero = self.context.f64_type().const_float(0.0);
                                self.builder.build_float_compare(
                                    FloatPredicate::ONE,
                                    self.builder.build_signed_int_to_float(
                                        i,
                                        self.context.f64_type(),
                                        "int_to_float",
                                    )?,
                                    zero,
                                    "neq_nil",
                                )
                            }
                            _ => panic!("Unsupported type in maybe: {result}"),
                        }?;
                        Ok(cond.as_basic_value_enum())
                    }

                    Expr::Get(obj, method)
                        if method == "replace"
                            && self
                                .infer_expr_type(obj)
                                .unwrap_or_else(|e| panic!("Type error: {e}"))
                                == Type::Str
                            && args.len() == 2 =>
                    {
                        let haystack_ptr = match self.compile_expr(obj)? {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(".replace() called on non-string value: {other:?}"),
                        };
                        let needle_ptr = match self.compile_expr(&args[0])? {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(".replace() needle must be a string, got {other:?}"),
                        };
                        let replacement_ptr = match self.compile_expr(&args[1])? {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(".replace() replacement must be a string, got {other:?}"),
                        };

                        let replace_fn = self.get_or_create_str_replace();
                        let call = self.builder.build_call(
                            replace_fn,
                            &[haystack_ptr.into(), needle_ptr.into(), replacement_ptr.into()],
                            "str_replace_call",
                        )?;
                        let result = call.try_as_basic_value().left().unwrap();
                        Ok(result)
                    }

                    Expr::Get(obj, method)
                        if method == "split"
                            && self
                                .infer_expr_type(obj)
                                .unwrap_or_else(|e| panic!("Type error: {e}"))
                                == Type::Str
                            && args.len() == 1 =>
                    {
                        let haystack_ptr = match self.compile_expr(obj)? {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(".split() called on non-string value: {other:?}"),
                        };
                        let delimiter_ptr = match self.compile_expr(&args[0])? {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(".split() delimiter must be a string, got {other:?}"),
                        };

                        let split_fn = self.get_or_create_str_split();
                        let call = self.builder.build_call(
                            split_fn,
                            &[haystack_ptr.into(), delimiter_ptr.into()],
                            "str_split_call",
                        )?;
                        let result = call.try_as_basic_value().left().unwrap();
                        Ok(result)
                    }

                    Expr::Get(obj, method)
                        if method == "starts_with"
                            && self
                                .infer_expr_type(obj)
                                .unwrap_or_else(|e| panic!("Type error: {e}"))
                                == Type::Str
                            && args.len() == 1 =>
                    {
                        let obj_val = match self.compile_expr(obj)? {
                            BasicValueEnum::PointerValue(p) => p,
                            _ => panic!(),
                        };

                        // Call C strncmp(s, needle, needle_len) and compare result to 0.
                        // strncmp returns 0 when the prefix matches, so we EQ against zero to get a boolean.
                        let strncmp_fn = self.get_or_create_strncmp();

                        // Argument 1: the needle string
                        let finding = self.compile_expr(&args[0])?;

                        // Argument 2: the needle length (i64 from .len()) cast to i32 expected by strncmp
                        let finding_len_val = self
                            .compile_expr(&Expr::Call(
                                Box::new(Expr::Get(Box::new(args[0].clone()), "len".to_string())),
                                vec![],
                            ))?
                            .into_int_value();
                        let finding_len_i32 = self.builder.build_int_truncate(
                            finding_len_val,
                            self.context.i32_type(),
                            "needle_len_i32",
                        )?;

                        // Call strncmp and compare to zero for a proper boolean
                        let call = self.builder.build_call(
                            strncmp_fn,
                            &[obj_val.into(), finding.into(), finding_len_i32.into()],
                            "strncmp_call",
                        )?;
                        let cmp = call
                            .try_as_basic_value()
                            .left()
                            .unwrap()
                            .into_int_value();
                        let zero = self.context.i32_type().const_int(0, false);
                        let is_prefix = self.builder.build_int_compare(
                            IntPredicate::EQ,
                            cmp,
                            zero,
                            "starts_with_bool",
                        )?;
                        Ok(is_prefix.as_basic_value_enum())
                    }

                    Expr::Get(obj, method)
                        if method == "ends_with"
                            && self
                                .infer_expr_type(obj)
                                .unwrap_or_else(|e| panic!("Type error: {e}"))
                                == Type::Str =>
                    {
                        // haystack pointer
                        let obj_ptr = match self.compile_expr(obj)? {
                            BasicValueEnum::PointerValue(p) => p,
                            _ => panic!(),
                        };

                        // needle pointer
                        let needle_ptr = self.compile_expr(&args[0])?;

                        // Compute lengths (i64)
                        let needle_len_i64 = self
                            .compile_expr(&Expr::Call(
                                Box::new(Expr::Get(Box::new(args[0].clone()), "len".to_string())),
                                vec![],
                            ))?
                            .into_int_value();
                        let hay_len_i64 = self
                            .compile_expr(&Expr::Call(
                                Box::new(Expr::Get(obj.clone(), "len".to_string())),
                                vec![],
                            ))?
                            .into_int_value();

                        // If needle is longer than haystack, ends_with is false. Compute offset = hay_len - needle_len
                        let offset = self
                            .builder
                            .build_int_sub(hay_len_i64, needle_len_i64, "ends_offset")?;

                        // Compute pointer to haystack end: hay + offset (byte-wise)
                        let i8_ty = self.context.i8_type();
                        let end_ptr = unsafe {
                            self.builder
                                .build_in_bounds_gep(i8_ty, obj_ptr, &[offset], "hay_end_ptr")?
                        };

                        // Compare suffix using strncmp(end_ptr, needle, needle_len)
                        let strncmp_fn = self.get_or_create_strncmp();
                        let needle_len_i32 = self.builder.build_int_truncate(
                            needle_len_i64,
                            self.context.i32_type(),
                            "needle_len_i32",
                        )?;
                        let call = self.builder.build_call(
                            strncmp_fn,
                            &[end_ptr.into(), needle_ptr.into(), needle_len_i32.into()],
                            "strncmp_suffix",
                        )?;
                        let cmp = call
                            .try_as_basic_value()
                            .left()
                            .unwrap()
                            .into_int_value();
                        let zero = self.context.i32_type().const_int(0, false);
                        let is_suffix = self.builder.build_int_compare(
                            IntPredicate::EQ,
                            cmp,
                            zero,
                            "ends_with_bool",
                        )?;
                        Ok(is_suffix.as_basic_value_enum())
                    }

                    Expr::Get(obj, method)
                        if method == "push"
                            && matches!(
                                self
                                    .infer_expr_type(obj)
                                    .unwrap_or_else(|e| panic!("Type error: {e}")),
                                Type::List(_)
                            ) =>
                    {
                        // Resolve list inner type to determine supported behavior
                        let inner_ty = match self.infer_expr_type(obj) {
                            Ok(Type::List(inner)) => *inner,
                            Ok(other) => panic!(".push() called on non-list type: {:?}", other),
                            Err(e) => panic!("Type error: {e}"),
                        };

                        if args.len() != 1 {
                            panic!(
                                "List::push expects exactly one argument, got {}",
                                args.len()
                            );
                        }

                        let f64_ty = self.context.f64_type();
                        let i64_ty = self.context.i64_type();

                        // Obtain the underlying buffer pointer
                        let original_buf_ptr = match self.compile_expr(obj)? {
                            BasicValueEnum::PointerValue(p) => p,
                            _ => panic!("List object not a pointer value"),
                        };

                        // Load current length from slot 0 (stored as f64)
                        let cur_len_f = self
                            .builder
                            .build_load(f64_ty, original_buf_ptr, "len_load")?
                            .into_float_value();
                        let cur_len_i = self
                            .builder
                            .build_float_to_signed_int(cur_len_f, i64_ty, "len_to_i64")?;

                        // Ensure capacity for the new element: reuse 8-byte slots for simplicity.
                        let slot_bytes = i64_ty.const_int(std::mem::size_of::<f64>() as u64, false);
                        let needed_slots = self.builder.build_int_add(
                            cur_len_i,
                            i64_ty.const_int(2, false),
                            "needed_slots",
                        )?; // len slot + existing elems + new elem
                        let total_bytes = self
                            .builder
                            .build_int_mul(slot_bytes, needed_slots, "push_bytes")?;
                        let realloc_fn = self.get_or_create_realloc();
                        let new_raw = self
                            .builder
                            .build_call(
                                realloc_fn,
                                &[original_buf_ptr.into(), total_bytes.into()],
                                "realloc_list_push",
                            )?
                            .try_as_basic_value()
                            .left()
                            .unwrap()
                            .into_pointer_value();

                        // Update the source variable if `obj` is a variable name
                        if let Expr::Variable(ref vname) = **obj {
                            if let Some(var_ptr) = self.vars.borrow().get(vname) {
                                let _ = self.builder.build_store(*var_ptr, new_raw);
                            }
                        }
                        let buf_ptr = new_raw;

                        // Compute insertion index = len + 1 (skip length slot at index 0)
                        let one = i64_ty.const_int(1, false);
                        let idx = self.builder.build_int_add(cur_len_i, one, "push_idx")?;
                        let elem_ptr = unsafe {
                            self.builder
                                .build_in_bounds_gep(f64_ty, buf_ptr, &[idx], "push_elem_ptr")?
                        };

                        // Compile the pushed value and convert it to the appropriate storage representation
                        let val = self.compile_expr(&args[0])?;
                        let value_to_store = match inner_ty {
                            Type::Num => match val {
                                BasicValueEnum::FloatValue(f) => f.as_basic_value_enum(),
                                BasicValueEnum::IntValue(iv) => self
                                    .builder
                                    .build_signed_int_to_float(iv, f64_ty, "int_to_float_push")?
                                    .as_basic_value_enum(),
                                other => panic!(
                                    "Attempted to push non-numeric value into numeric list: {:?}",
                                    other
                                ),
                            },
                            Type::Bool => match val {
                                BasicValueEnum::IntValue(iv) => {
                                    if iv.get_type().get_bit_width() == 1 {
                                        iv.as_basic_value_enum()
                                    } else {
                                        let zero = iv.get_type().const_zero();
                                        self.builder
                                            .build_int_compare(
                                                IntPredicate::NE,
                                                iv,
                                                zero,
                                                "int_to_bool_push",
                                            )?
                                            .as_basic_value_enum()
                                    }
                                }
                                BasicValueEnum::FloatValue(fv) => {
                                    let zero = f64_ty.const_float(0.0);
                                    self.builder
                                        .build_float_compare(
                                            FloatPredicate::ONE,
                                            fv,
                                            zero,
                                            "float_to_bool_push",
                                        )?
                                        .as_basic_value_enum()
                                }
                                other => panic!(
                                    "Attempted to push non-boolean value into bool list: {:?}",
                                    other
                                ),
                            },
                            Type::Nil => match val {
                                BasicValueEnum::PointerValue(p) => p.as_basic_value_enum(),
                                BasicValueEnum::FloatValue(f) => f.as_basic_value_enum(),
                                BasicValueEnum::IntValue(iv) => {
                                    if iv.get_type().get_bit_width() == 1 {
                                        iv.as_basic_value_enum()
                                    } else {
                                        self
                                            .builder
                                            .build_signed_int_to_float(
                                                iv,
                                                f64_ty,
                                                "int_to_float_push",
                                            )?
                                            .as_basic_value_enum()
                                    }
                                }
                                other => panic!(
                                    "Attempted to push unsupported value into untyped list: {:?}",
                                    other
                                ),
                            },
                            Type::Str
                            | Type::Custom(_)
                            | Type::Option(_)
                            | Type::List(_)
                            | Type::Io
                            | Type::WebReturn
                            | Type::RangeBuilder
                            | Type::Kv(_)
                            | Type::Function(_, _) => match val {
                                BasicValueEnum::PointerValue(p) => p.as_basic_value_enum(),
                                other => panic!(
                                    "Attempted to push non-pointer value into pointer list: {:?}",
                                    other
                                ),
                            },
                        };

                        let _ = self.builder.build_store(elem_ptr, value_to_store);

                        // Update length in slot 0: len += 1
                        let new_len_i = self.builder.build_int_add(cur_len_i, one, "len_inc")?;
                        let new_len_f = self
                            .builder
                            .build_signed_int_to_float(new_len_i, f64_ty, "len_to_f64")?;
                        let _ = self.builder.build_store(buf_ptr, new_len_f);

                        Ok(f64_ty.const_float(0.0).as_basic_value_enum())
                    }

                    Expr::Get(obj, met)
                        if met == "default"
                            && matches!(self.infer_expr_type(obj), Ok(Type::Option(_))) =>
                    {
                        if args.len() != 1 {
                            panic!(
                                "Option::default expects exactly one argument (the fallback value), got {}",
                                args.len()
                            );
                        }

                        let option_val = self.compile_expr(obj)?;
                        let default_val = self.compile_expr(&args[0])?;

                        let selected = match (option_val, default_val) {
                            (
                                BasicValueEnum::PointerValue(opt_ptr),
                                BasicValueEnum::PointerValue(default_ptr),
                            ) => {
                                let null_ptr = opt_ptr.get_type().const_null();
                                let has_value = self.builder.build_int_compare(
                                    IntPredicate::NE,
                                    opt_ptr,
                                    null_ptr,
                                    "option_default_has_value",
                                )?;
                                self.builder.build_select(
                                    has_value,
                                    opt_ptr.as_basic_value_enum(),
                                    default_ptr.as_basic_value_enum(),
                                    "option_default_select",
                                )?
                            }
                            (
                                BasicValueEnum::FloatValue(opt_float),
                                BasicValueEnum::FloatValue(default_float),
                            ) => {
                                let zero = self.context.f64_type().const_float(0.0);
                                let has_value = self.builder.build_float_compare(
                                    FloatPredicate::ONE,
                                    opt_float,
                                    zero,
                                    "option_default_has_value",
                                )?;
                                self.builder.build_select(
                                    has_value,
                                    opt_float.as_basic_value_enum(),
                                    default_float.as_basic_value_enum(),
                                    "option_default_select",
                                )?
                            }
                            (
                                BasicValueEnum::IntValue(opt_int),
                                BasicValueEnum::IntValue(default_int),
                            ) => {
                                let zero = opt_int.get_type().const_zero();
                                let has_value = self.builder.build_int_compare(
                                    IntPredicate::NE,
                                    opt_int,
                                    zero,
                                    "option_default_has_value",
                                )?;
                                self.builder.build_select(
                                    has_value,
                                    opt_int.as_basic_value_enum(),
                                    default_int.as_basic_value_enum(),
                                    "option_default_select",
                                )?
                            }
                            other => panic!(
                                "Option::default is not implemented for value combination: {other:?}"
                            ),
                        };

                        Ok(selected)
                    }


                    _ => {
                        panic!("Unsupported call expression: {callee:?}");
                    }
                }
            }
            Expr::List(items) => {
                let count = items.len() as u64;
                let f64_ty = self.context.f64_type();

                // Allocate count + 1 elements to store the length at the beginning
                let total_bytes = {
                    let bytes_per = self
                        .context
                        .i64_type()
                        .const_int(std::mem::size_of::<f64>() as u64, false);
                    let num_elems = self.context.i64_type().const_int(count + 1, false);
                    self.builder
                        .build_int_mul(bytes_per, num_elems, "list_bytes")?
                };

                // Malloc buffer
                let malloc_fn = self.get_or_create_malloc();
                let raw_ptr =
                    self.builder
                        .build_call(malloc_fn, &[total_bytes.into()], "malloc")?;
                let raw_ptr = raw_ptr
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();
                let f64_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let buf_ptr =
                    self.builder
                        .build_pointer_cast(raw_ptr, f64_ptr_ty, "list_buf_ptr")?;

                // Store length at index 0
                let len_val = f64_ty.const_float(count as f64);
                let len_ptr = unsafe {
                    // GEP by element type (f64) to scale correctly under opaque pointers
                    self.builder.build_in_bounds_gep(
                        f64_ty,
                        buf_ptr,
                        &[self.context.i64_type().const_int(0, false)],
                        "len_ptr",
                    )?
                };
                let _ = self.builder.build_store(len_ptr, len_val);

                // Store each element starting from index 1
                for (idx, item) in items.iter().enumerate() {
                    let elem_val = self.compile_expr(item)?;
                    let idx_val = self.context.i64_type().const_int((idx + 1) as u64, false);
                    let gep = unsafe {
                        // Index using f64 element type for correct scaling
                        self.builder
                            .build_in_bounds_gep(f64_ty, buf_ptr, &[idx_val], "elem_ptr")?
                    };
                    let _ = self.builder.build_store(gep, elem_val);
                }

                Ok(buf_ptr.as_basic_value_enum())
            }
            Expr::Index(list, indexed_by) => {
                // Determine the static type of the left-hand side to decide behavior
                let lhs_type = self
                    .infer_expr_type(list)
                    .expect("Unable to resolve type for indexing");

                let lhs_val = self.compile_expr(list)?;
                let index_val = self.compile_expr(indexed_by)?;

                // Index must be integer (or numeric convertible)
                let idx = match index_val {
                    BasicValueEnum::IntValue(i) => i,
                    BasicValueEnum::FloatValue(f) => self.builder.build_float_to_signed_int(
                        f,
                        self.context.i64_type(),
                        "number",
                    )?,
                    _ => panic!("Index must be integer: {:?}", index_val),
                };

                match lhs_type {
                    // String indexing -> return a new 1-character C-string
                    Type::Str => {
                        let str_ptr = match lhs_val {
                            BasicValueEnum::PointerValue(p) => p,
                            _ => panic!("String index on non-pointer value: {:?}", lhs_val),
                        };

                        // Compute address of the target character: &str[idx]
                        let i8_ty = self.context.i8_type();
                        let i8_ptr_ty = i8_ty.ptr_type(AddressSpace::default());
                        let char_ptr = unsafe {
                            // Use i8 element type for byte-wise indexing
                            self.builder
                                .build_in_bounds_gep(i8_ty, str_ptr, &[idx], "char_ptr")?
                        };

                        // Load the byte at that index
                        let ch = self
                            .builder
                            .build_load(i8_ty, char_ptr, "load_char")
                            .unwrap()
                            .into_int_value();

                        // Allocate a 2-byte buffer: character + null terminator
                        let malloc_fn = self.get_or_create_malloc();
                        let two = self.context.i64_type().const_int(2, false);
                        let buf_raw = self
                            .builder
                            .build_call(malloc_fn, &[two.into()], "malloc_char")?
                            .try_as_basic_value()
                            .left()
                            .unwrap()
                            .into_pointer_value();
                        let buf_ptr =
                            self.builder
                                .build_pointer_cast(buf_raw, i8_ptr_ty, "char_buf_ptr")?;

                        // Store the character and the null terminator
                        let zero = i8_ty.const_int(0, false);
                        let first_ptr = unsafe {
                            self.builder.build_in_bounds_gep(
                                i8_ty,
                                buf_ptr,
                                &[self.context.i64_type().const_int(0, false)],
                                "buf_0",
                            )?
                        };
                        let second_ptr = unsafe {
                            self.builder.build_in_bounds_gep(
                                i8_ty,
                                buf_ptr,
                                &[self.context.i64_type().const_int(1, false)],
                                "buf_1",
                            )?
                        };
                        let _ = self.builder.build_store(first_ptr, ch);
                        let _ = self.builder.build_store(second_ptr, zero);

                        Ok(buf_ptr.as_basic_value_enum())
                    }
                    // List indexing: load element based on inner type
                    Type::List(inner) => {
                        let list_ptr = match lhs_val {
                            BasicValueEnum::PointerValue(p) => p,
                            _ => panic!("Index on non-list pointer: {:?}", lhs_val),
                        };

                        // skip the length slot at index 0
                        let one = self.context.i64_type().const_int(1, false);
                        let idx1 = self.builder.build_int_add(idx, one, "idx_plus1")?;

                        // address of element slot using 8-byte stride (f64)
                        let f64_ty = self.context.f64_type();
                        let elem_ptr = unsafe {
                            self.builder.build_in_bounds_gep(
                                f64_ty,
                                list_ptr,
                                &[idx1],
                                "list_index",
                            )?
                        };

                        match *inner {
                            Type::Num => {
                                let loaded = self
                                    .builder
                                    .build_load(self.context.f64_type(), elem_ptr, "load_num_elem")
                                    .unwrap();
                                Ok(loaded)
                            }
                            Type::Str => {
                                let ptr_ty = self.context.ptr_type(AddressSpace::default());
                                let loaded = self
                                    .builder
                                    .build_load(ptr_ty, elem_ptr, "load_str_elem")
                                    .unwrap();
                                Ok(loaded)
                            }
                            Type::Custom(_)
                            | Type::Option(_)
                            | Type::List(_)
                            | Type::Io
                            | Type::WebReturn
                            | Type::RangeBuilder
                            | Type::Kv(_)
                            | Type::Function(_, _) => {
                                let ptr_ty = self.context.ptr_type(AddressSpace::default());
                                let loaded = self
                                    .builder
                                    .build_load(ptr_ty, elem_ptr, "load_ptr_elem")
                                    .unwrap();
                                Ok(loaded)
                            }
                            _ => panic!("Indexing not supported on list inner type"),
                        }
                    }
                    other => panic!("Indexing not supported on type: {:?}", other),
                }
            }
            Expr::Function(params, ret_type, body) => {
                // Generate a unique name for each anonymous function and compile it in isolation
                let id = INLINE_FN_COUNTER.fetch_add(1, Ordering::Relaxed);
                let name = format!("inline_fn_{}", id);

                // Capture the current variable bindings so we can snapshot the environment
                let captured_bindings = self.vars.borrow().clone();
                let captured_types = self.var_types.borrow().clone();
                let mut capture_map: HashMap<String, CaptureDescriptor<'ctx>> = HashMap::new();
                let ptr_ty = self.context.ptr_type(AddressSpace::default());

                for (var_name, _) in &captured_bindings {
                    if params.iter().any(|(param_name, _)| param_name == var_name) {
                        continue;
                    }
                    if let Some(ty) = captured_types.get(var_name) {
                        let global_name = format!("inline_env_{}_{}", id, var_name);
                        let global = if let Some(existing) = self.module.get_global(&global_name) {
                            existing
                        } else {
                            let g = self
                                .module
                                .add_global(ptr_ty.as_basic_type_enum(), None, &global_name);
                            g.set_linkage(Linkage::Internal);
                            g.set_initializer(&ptr_ty.const_null().as_basic_value_enum());
                            g
                        };
                        // Ensure the global stays referenced so LLVM keeps it alive
                        let _ = global;
                        capture_map.insert(
                            var_name.clone(),
                            CaptureDescriptor {
                                global_name: global_name.clone(),
                                ty: *ty,
                            },
                        );
                    }
                }

                if capture_map.is_empty() {
                    self.closure_envs.borrow_mut().remove(&name);
                } else {
                    self.closure_envs
                        .borrow_mut()
                        .insert(name.clone(), capture_map.clone());
                }

                // Remember current insertion point so we can restore it after compiling the anon fn
                let saved_insert_block = self.builder.get_insert_block();
                let parent_fn = saved_insert_block.and_then(|bb| bb.get_parent());

                // Compile as a proper function definition
                self.compile_instruction(
                    parent_fn.unwrap_or_else(|| self.module.get_last_function().unwrap()),
                    &Instruction::FunctionDef {
                        name: name.clone(),
                        params: params.to_vec(),
                        return_type: ret_type.clone(),
                        body: vec![body.as_ref().clone()],
                    },
                )?;

                // Restore builder insertion point for the caller function
                if let Some(bb) = saved_insert_block {
                    self.builder.position_at_end(bb);
                }

                // Store the current bindings into the capture globals so the closure can access them
                if !capture_map.is_empty() {
                    for (var_name, descriptor) in &capture_map {
                        if let Some(ptr_value) = captured_bindings.get(var_name) {
                            if let Some(global) = self.module.get_global(&descriptor.global_name) {
                                let cast_ptr = self
                                    .builder
                                    .build_pointer_cast(
                                        *ptr_value,
                                        ptr_ty,
                                        &format!("{var_name}_env_capture_ptr_{id}"),
                                    )
                                    .unwrap();
                                self.builder
                                    .build_store(
                                        global.as_pointer_value(),
                                        cast_ptr.as_basic_value_enum(),
                                    )?;
                            }
                        }
                    }
                }

                if let Some(func) = self.module.get_function(&name) {
                    let fn_ptr_val = func.as_global_value().as_pointer_value();
                    Ok(self
                        .builder
                        .build_pointer_cast(
                            fn_ptr_val,
                            self.context.ptr_type(AddressSpace::default()),
                            "fn_ptr_cast",
                        )
                        .unwrap()
                        .as_basic_value_enum())
                } else {
                    panic!()
                }
            }

            Expr::Unary(op, ex) => {
                match op {
                    Unary::Not => {
                        let val = self.compile_expr(ex)?;
                        Ok(self.builder.build_int_compare(IntPredicate::EQ, val.into_int_value(), self.context.bool_type().const_int(0, false), "not_op")?.as_basic_value_enum())
                    }
                    Unary::Neg => {
                        let val = self.compile_expr(ex)?;
                        Ok(self.builder.build_float_neg(val.into_float_value(), "negative")?.as_basic_value_enum())
                    }
                }
            }

            _ => panic!("Unsupported expression in compile_expr: {expr:?}"),
        }
    }
    fn get_or_create_strcmp(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("strcmp") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // strcmp signature: (i8*, i8*) -> i32
            let fn_type = self
                .context
                .i32_type()
                .fn_type(&[i8ptr.into(), i8ptr.into()], false);
            self.module.add_function("strcmp", fn_type, None)
        }
    }
    fn get_or_create_strncmp(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("strncmp") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // strcmp signature: (i8*, i8*) -> i32
            let fn_type = self.context.i32_type().fn_type(
                &[i8ptr.into(), i8ptr.into(), self.context.i32_type().into()],
                false,
            );
            self.module.add_function("strncmp", fn_type, None)
        }
    }

    fn get_or_create_strlen(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("strlen") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // strlen signature: (i8*) -> i64
            let fn_type = self.context.i64_type().fn_type(&[i8ptr.into()], false);
            self.module.add_function("strlen", fn_type, None)
        }
    }

    fn get_or_create_atoi(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("atoi") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // strlen signature: (i8*) -> i64
            let fn_type = self.context.i64_type().fn_type(&[i8ptr.into()], false);
            self.module.add_function("atoi", fn_type, None)
        }
    }

    fn get_or_create_strstr(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("strstr") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // strstr signature: (i8*, i8*) -> i8*
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false);
            self.module.add_function("strstr", fn_type, None)
        }
    }

    fn get_or_create_str_replace(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("qs_str_replace") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), i8ptr.into(), i8ptr.into()], false);
            self.module.add_function("qs_str_replace", fn_type, None)
        }
    }

    fn get_or_create_str_split(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("qs_str_split") {
            f
        } else {
            let ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = ptr.fn_type(&[ptr.into(), ptr.into()], false);
            self.module.add_function("qs_str_split", fn_type, None)
        }
    }

    fn get_or_create_malloc(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("malloc") {
            f
        } else {
            let i64_type = self.context.i64_type();
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // malloc signature: (i64) -> i8*
            let fn_type = i8ptr.fn_type(&[i64_type.into()], false);
            self.module.add_function("malloc", fn_type, None)
        }
    }

    fn get_or_create_strcpy(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("strcpy") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // strcpy signature: (i8*, i8*) -> i8*
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false);
            self.module.add_function("strcpy", fn_type, None)
        }
    }

    fn get_or_create_strcat_c(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("strcat") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            // strcat signature: (i8*, i8*) -> i8*
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false);
            self.module.add_function("strcat", fn_type, None)
        }
    }

    fn get_or_create_realloc(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("realloc") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            // realloc signature: (i8*, i64) -> i8*
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), i64_type.into()], false);
            self.module.add_function("realloc", fn_type, None)
        }
    }

    fn get_or_create_memcpy(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("memcpy") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            // memcpy signature: (i8*, i8*, i64) -> i8*
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), i8ptr.into(), i64_type.into()], false);
            self.module.add_function("memcpy", fn_type, None)
        }
    }

    fn get_or_create_fgets(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("fgets") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i32_type = self.context.i32_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            // fgets signature: (i8*, i32, void*) -> i8*
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), i32_type.into(), void_ptr.into()], false);
            self.module.add_function("fgets", fn_type, None)
        }
    }

    fn get_or_create_get_stdin(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_stdin") {
            f
        } else {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            // stdin signature: () -> void*
            let fn_type = void_ptr.fn_type(&[], false);
            self.module.add_function("get_stdin", fn_type, None)
        }
    }

    fn get_or_create_qs_listen_with_callback(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("qs_listen_with_callback") {
            f
        } else {
            let i32t = self.context.i32_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = self
                .context
                .void_type()
                .fn_type(&[i32t.into(), void_ptr.into()], false);
            self.module
                .add_function("qs_listen_with_callback", fn_type, None)
        }
    }

    fn get_or_create_create_request_object(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("create_request_object") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(
                &[
                    i8ptr.into(),
                    i8ptr.into(),
                    i8ptr.into(),
                    i8ptr.into(),
                    i8ptr.into(),
                ],
                false,
            );
            self.module
                .add_function("create_request_object", fn_type, None)
        }
    }

    fn get_or_create_get_request_method(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_request_method") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module
                .add_function("get_request_method", fn_type, None)
        }
    }

    fn get_or_create_get_request_path(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_request_path") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("get_request_path", fn_type, None)
        }
    }

    fn get_or_create_get_request_body(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_request_body") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("get_request_body", fn_type, None)
        }
    }

    fn get_or_create_get_request_query(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_request_query") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("get_request_query", fn_type, None)
        }
    }

    fn get_or_create_get_request_headers(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_request_headers") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module
                .add_function("get_request_headers", fn_type, None)
        }
    }

    fn get_or_create_web_helper(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("create_web_helper") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[], false);
            self.module.add_function("create_web_helper", fn_type, None)
        }
    }

    fn get_or_create_range_builder(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("create_range_builder") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[], false);
            self.module
                .add_function("create_range_builder", fn_type, None)
        }
    }

    fn get_or_create_range_builder_to(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("create_range_builder_to") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(
                &[
                    BasicMetadataTypeEnum::PointerType(
                        self.context.ptr_type(AddressSpace::default()),
                    )
                    .into(),
                    self.context.f64_type().into(),
                ],
                false,
            );
            self.module
                .add_function("create_range_builder_to", fn_type, None)
        }
    }

    fn get_or_create_range_builder_from(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("create_range_builder_from") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(
                &[
                    BasicMetadataTypeEnum::PointerType(
                        self.context.ptr_type(AddressSpace::default()),
                    )
                    .into(),
                    self.context.f64_type().into(),
                ],
                false,
            );
            self.module
                .add_function("create_range_builder_from", fn_type, None)
        }
    }

    fn get_or_create_range_builder_step(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("create_range_builder_step") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(
                &[
                    BasicMetadataTypeEnum::PointerType(
                        self.context.ptr_type(AddressSpace::default()),
                    )
                    .into(),
                    self.context.f64_type().into(),
                ],
                false,
            );
            self.module
                .add_function("create_range_builder_step", fn_type, None)
        }
    }

    fn get_or_create_range_builder_get_from(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("range_builder_get_from") {
            f
        } else {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            let fn_type = self.context.f64_type().fn_type(&[ptr_ty.into()], false);
            self.module
                .add_function("range_builder_get_from", fn_type, None)
        }
    }

    fn get_or_create_range_builder_get_to(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("range_builder_get_to") {
            f
        } else {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            let fn_type = self.context.f64_type().fn_type(&[ptr_ty.into()], false);
            self.module
                .add_function("range_builder_get_to", fn_type, None)
        }
    }

    fn get_or_create_range_builder_get_step(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("range_builder_get_step") {
            f
        } else {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            let fn_type = self.context.f64_type().fn_type(&[ptr_ty.into()], false);
            self.module
                .add_function("range_builder_get_step", fn_type, None)
        }
    }

    fn get_or_create_io_read_file(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("io_read_file") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("io_read_file", fn_type, None)
        }
    }

    fn get_or_create_io_write_file(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("io_write_file") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let f64_type = self.context.f64_type();
            let fn_type = f64_type.fn_type(&[i8ptr.into(), i8ptr.into()], false);
            self.module.add_function("io_write_file", fn_type, None)
        }
    }

    fn get_or_create_web_text(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("web_text") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("web_text", fn_type, None)
        }
    }

    fn get_or_create_web_json(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("web_json") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("web_json", fn_type, None)
        }
    }

    fn get_or_create_web_file(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("web_file") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("web_file", fn_type, None)
        }
    }

    fn get_or_create_web_page(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("web_page") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i8ptr.into()], false);
            self.module.add_function("web_page", fn_type, None)
        }
    }

    fn get_or_create_web_error_text(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("web_error_text") {
            f
        } else {
            let i32t = self.context.i32_type();
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i32t.into(), i8ptr.into()], false);
            self.module.add_function("web_error_text", fn_type, None)
        }
    }

    fn get_or_create_web_error_page(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("web_error_page") {
            f
        } else {
            let i32t = self.context.i32_type();
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[i32t.into(), i8ptr.into()], false);
            self.module.add_function("web_error_page", fn_type, None)
        }
    }

    fn get_or_create_web_redirect(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("web_redirect") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let bool_type = self.context.bool_type();
            let fn_type = i8ptr.fn_type(&[i8ptr.into(), bool_type.into()], false);
            self.module.add_function("web_redirect", fn_type, None)
        }
    }

    fn get_or_create_get_current_method(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_current_method") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[], false);
            self.module
                .add_function("get_current_method", fn_type, None)
        }
    }

    fn get_or_create_get_current_path(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("get_current_path") {
            f
        } else {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = i8ptr.fn_type(&[], false);
            self.module.add_function("get_current_path", fn_type, None)
        }
    }

    // ───── Obj (Kv) extern bindings ─────
    fn get_or_create_qs_obj_new(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("qs_obj_new") {
            f
        } else {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = void_ptr.fn_type(&[], false);
            self.module.add_function("qs_obj_new", fn_type, None)
        }
    }

    fn get_or_create_qs_obj_insert_str(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("qs_obj_insert_str") {
            f
        } else {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = self
                .context
                .void_type()
                .fn_type(&[void_ptr.into(), i8ptr.into(), void_ptr.into()], false);
            self.module.add_function("qs_obj_insert_str", fn_type, None)
        }
    }

    fn get_or_create_qs_obj_get_str(&self) -> FunctionValue<'ctx> {
        if let Some(f) = self.module.get_function("qs_obj_get_str") {
            f
        } else {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = void_ptr.fn_type(&[void_ptr.into(), i8ptr.into()], false);
            self.module.add_function("qs_obj_get_str", fn_type, None)
        }
    }

    fn compile_safe_string_append(
        &self,
        var_name: &str,
        append_expr: &Expr,
    ) -> Result<(), BuilderError> {
        // For now, disable the optimization and fall back to regular concatenation
        // The current approach is still O(n²) and causes performance issues
        // TODO: Implement a true O(n) string builder with persistent buffer management

        let new_c = self.compile_expr(&Expr::Binary(
            Box::new(Expr::Variable(var_name.to_string())),
            BinOp::Plus,
            Box::new(append_expr.clone()),
        ))?;

        let binding = self.vars.borrow();
        let var_ptr = binding
            .get(var_name)
            .unwrap_or_else(|| panic!("Variable not found: {var_name}"));
        self.builder.build_store(*var_ptr, new_c)?;

        Ok(())
    }
}

fn format_float(lexeme: &str) -> String {
    if lexeme.contains('.') {
        let mut s = lexeme.trim_end_matches('0').to_string();
        if s.ends_with('.') {
            s.push('0');
        }
        s
    } else {
        format!("{}.0", lexeme)
    }
}

fn tokenize(chars: Vec<char>) -> Vec<Token> {
    let mut is_commented = false;
    let mut in_string = false;
    let mut current_string = String::new();
    let mut string_escape = false;

    let mut tokens = vec![];
    let mut line = 1;
    let mut index = 0;

    while index < chars.len() {
        let current_char = chars[index];

        if in_string {
            if string_escape {
                match current_char {
                    '"' => {
                        current_string.push('"');
                        index += 1;
                        string_escape = false;
                        continue;
                    }
                    '\\' => {
                        current_string.push('\\');
                        index += 1;
                        string_escape = false;
                        continue;
                    }
                    'n' => {
                        current_string.push('\n');
                        index += 1;
                        string_escape = false;
                        continue;
                    }
                    'r' => {
                        current_string.push('\r');
                        index += 1;
                        string_escape = false;
                        continue;
                    }
                    't' => {
                        current_string.push('\t');
                        index += 1;
                        string_escape = false;
                        continue;
                    }
                    '0' => {
                        current_string.push('\0');
                        index += 1;
                        string_escape = false;
                        continue;
                    }
                    '\'' => {
                        current_string.push('\'');
                        index += 1;
                        string_escape = false;
                        continue;
                    }
                    'x' => {
                        if index + 2 < chars.len() {
                            let hi = chars[index + 1];
                            let lo = chars[index + 2];
                            if let (Some(high), Some(low)) = (hi.to_digit(16), lo.to_digit(16)) {
                                let value = ((high << 4) | low) as u32;
                                if let Some(ch) = std::char::from_u32(value) {
                                    current_string.push(ch);
                                    index += 3;
                                    string_escape = false;
                                    continue;
                                }
                            }
                        }
                        current_string.push('\\');
                        string_escape = false;
                        continue;
                    }
                    'u' => {
                        if index + 1 < chars.len() && chars[index + 1] == '{' {
                            let mut j = index + 2;
                            let mut digits = 0;
                            let mut value: u32 = 0;
                            while j < chars.len() {
                                let c = chars[j];
                                if c == '}' {
                                    break;
                                }
                                if let Some(d) = c.to_digit(16) {
                                    if digits >= 6 {
                                        digits = 7; // mark invalid
                                        break;
                                    }
                                    value = (value << 4) | d;
                                    digits += 1;
                                    j += 1;
                                } else {
                                    digits = 7; // mark invalid
                                    break;
                                }
                            }
                            if j < chars.len() && chars[j] == '}' && digits > 0 && digits <= 6 {
                                if let Some(ch) = std::char::from_u32(value) {
                                    current_string.push(ch);
                                    index = j + 1;
                                    string_escape = false;
                                    continue;
                                }
                            }
                        }
                        current_string.push('\\');
                        string_escape = false;
                        continue;
                    }
                    _ => {
                        current_string.push('\\');
                        string_escape = false;
                        continue;
                    }
                }
            } else {
                match current_char {
                    '\\' => {
                        string_escape = true;
                        index += 1;
                        continue;
                    }
                    '"' => {
                        let string_value = std::mem::take(&mut current_string);
                        let value_copy = string_value.clone();
                        tokens.push(Token {
                            value: value_copy,
                            kind: Str(string_value),
                            line,
                        });
                        in_string = false;
                        string_escape = false;
                        index += 1;
                        continue;
                    }
                    '\n' => {
                        current_string.push('\n');
                        line += 1;
                        index += 1;
                        continue;
                    }
                    _ => {
                        current_string.push(current_char);
                        index += 1;
                        continue;
                    }
                }
            }
        }

        if is_commented {
            if current_char == '\n' {
                is_commented = false;
                line += 1;
            }
            index += 1;
            continue;
        }

        if current_char == '"' {
            in_string = true;
            string_escape = false;
            current_string.clear();
            index += 1;
            continue;
        }

        if current_char == '\n' {
            line += 1;
            index += 1;
            continue;
        }
        if current_char == ' ' || current_char == '\t' {
            index += 1;
            continue;
        }

        // Handle numbers
        if current_char.is_ascii_digit()
            || (current_char == '.' && index + 1 < chars.len() && chars[index + 1].is_ascii_digit())
        {
            let mut number_str = String::new();
            let mut has_dot = false;
            let mut j = index;

            while j < chars.len() {
                let c = chars[j];
                if c.is_ascii_digit() {
                    number_str.push(c);
                } else if c == '.' && !has_dot {
                    number_str.push(c);
                    has_dot = true;
                } else {
                    break;
                }
                j += 1;
            }

            if let Ok(num_val) = number_str.parse::<f64>() {
                tokens.push(Token {
                    value: number_str,
                    kind: Num(num_val),
                    line,
                });
                index = j;
                continue;
            }
        }

        // Handle identifiers
        if current_char.is_alphabetic() || current_char == '_' {
            let mut identifier = String::new();
            let mut j = index;

            while j < chars.len() && is_identifier_char(chars[j]) {
                identifier.push(chars[j]);
                j += 1;
            }

            tokens.push(Token {
                value: identifier.clone(),
                kind: get_special_ident(identifier),
                line,
            });
            index = j;
            continue;
        }

        // Handle two-character operators
        if index + 1 < chars.len() {
            let next_char = chars[index + 1];
            let two_char = format!("{}{}", current_char, next_char);

            match two_char.as_str() {
                "==" => {
                    tokens.push(Token {
                        value: "==".to_string(),
                        kind: EqualEqual,
                        line,
                    });
                    index += 2;
                    continue;
                }
                "!=" => {
                    tokens.push(Token {
                        value: "!=".to_string(),
                        kind: BangEqual,
                        line,
                    });
                    index += 2;
                    continue;
                }
                "<=" => {
                    tokens.push(Token {
                        value: "<=".to_string(),
                        kind: LessEqual,
                        line,
                    });
                    index += 2;
                    continue;
                }
                ">=" => {
                    tokens.push(Token {
                        value: ">=".to_string(),
                        kind: GreaterEqual,
                        line,
                    });
                    index += 2;
                    continue;
                }
                "=>" => {
                    tokens.push(Token {
                        value: "=>".to_string(),
                        kind: BigArrow,
                        line,
                    });
                    index += 2;
                    continue;
                }
                "&&" => {
                    tokens.push(Token {
                        value: "&&".to_string(),
                        kind: TokenKind::AmpAmp,
                        line,
                    });
                    index += 2;
                    continue;
                }
                "||" => {
                    tokens.push(Token {
                        value: "||".to_string(),
                        kind: TokenKind::PipePipe,
                        line,
                    });
                    index += 2;
                    continue;
                }
                "//" => {
                    is_commented = true;
                    index += 2;
                    continue;
                }
                _ => {}
            }
        }

        // Handle single-character tokens
        if let Some(token_kind) = is_single_char_token(current_char) {
            tokens.push(Token {
                value: current_char.to_string(),
                kind: token_kind,
                line,
            });
            index += 1;
            continue;
        }

        // Handle single-character operators
        match current_char {
            '=' => {
                tokens.push(Token {
                    value: "=".to_string(),
                    kind: Equal,
                    line,
                });
            }
            '!' => {
                tokens.push(Token {
                    value: "!".to_string(),
                    kind: Bang,
                    line,
                });
            }
            '<' => {
                tokens.push(Token {
                    value: "<".to_string(),
                    kind: Less,
                    line,
                });
            }
            '>' => {
                tokens.push(Token {
                    value: ">".to_string(),
                    kind: Greater,
                    line,
                });
            }
            '/' => {
                tokens.push(Token {
                    value: "/".to_string(),
                    kind: Slash,
                    line,
                });
            }
            '[' => {
                tokens.push(Token {
                    value: "[".to_string(),
                    kind: TokenKind::LBrack,
                    line,
                });
            }
            ']' => {
                tokens.push(Token {
                    value: "]".to_string(),
                    kind: TokenKind::RBrack,
                    line,
                });
            }
            _ => {
                tokens.push(Token {
                    value: "".to_string(),
                    kind: Error(
                        line as u64,
                        format!("Unexpected character: {}", current_char),
                    ),
                    line,
                });
            }
        }
        index += 1;
    }

    if in_string {
        tokens.push(Token {
            value: "".to_string(),
            kind: Error(line as u64, "Unterminated string.".to_string()),
            line,
        });
    }
    // if tokens.len() > 1 || !has_error {
    tokens.push(Token {
        value: "EOF".to_string(),
        kind: Eof,
        line,
    });
    // }

    tokens
}
