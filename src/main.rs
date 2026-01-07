mod compiler;
mod parser;
use crate::TokenKind::*;
use crate::compiler::CodegenMode;
use clap::Parser as Clap;
use parser::Parser;

use crate::compiler::Compiler;
use inkwell::AddressSpace;
#[cfg(not(feature = "runtime-lib"))]
static LIBQUICK: &'static [u8] = include_bytes!("../target/runtime/release/libquick_runtime.a");
unsafe extern "C" {
    fn strcmp(a: *const i8, b: *const i8) -> i32;
    fn strncmp(a: *const i8, b: *const i8, c: i32) -> i32;
    fn printf(fmt: *const i8, ...) -> i32;
    fn strcpy(dest: *mut i8, src: *const i8) -> *mut i8;
    fn sprintf(buf: *mut i8, fmt: *const i8, ...) -> i32;
    fn strcat(dest: *mut i8, src: *const i8) -> *mut i8;
    fn strlen(s: *const i8) -> usize;
    fn atoi(s: *const i8) -> usize;
    // Correct strstr signature: returns pointer to match or NULL
    fn strstr(s: *const i8, o: *const i8) -> *mut i8;

    fn memcpy(dest: *mut i8, src: *const i8, n: usize) -> *mut i8;

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
    fn LLVMLinkInMCJIT();
    fn LLVMLinkInInterpreter();

}

pub static mut GLOBAL_ARENA_PTR: *mut Arena = std::ptr::null_mut();
static ARENA_DEBUG_CHECKS: AtomicBool = AtomicBool::new(false);

fn get_or_create_global_arena() -> *mut Arena {
    unsafe {
        if GLOBAL_ARENA_PTR.is_null() {
            GLOBAL_ARENA_PTR = arena_create(64 * 1024 * 1024);
        }
        GLOBAL_ARENA_PTR
    }
}

fn alloc_in_arena(size: usize, align: usize) -> *mut c_void {
    unsafe {
        let arena = get_or_create_global_arena();
        arena_alloc(arena, size, align) as *mut c_void
    }
}

fn arena_alloc_cstring(bytes: &[u8]) -> *mut c_char {
    unsafe {
        let len = bytes.len().saturating_add(1);
        let buf = alloc_in_arena(len, 1) as *mut u8;
        if buf.is_null() {
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
        *buf.add(bytes.len()) = 0;
        buf as *mut c_char
    }
}

fn arena_cstring_from_bytes_checked(bytes: &[u8]) -> *mut c_char {
    if bytes.contains(&0) {
        std::ptr::null_mut()
    } else {
        arena_alloc_cstring(bytes)
    }
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
    inner: HashMap<CString, *mut c_void>,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct QsResult {
    is_ok: bool,
    ok: *mut c_void,
    err: *mut c_void,
}

fn qs_result_ok(value: *mut c_void) -> *mut c_void {
    let result = QsResult {
        is_ok: true,
        ok: value,
        err: std::ptr::null_mut(),
    };
    Box::into_raw(Box::new(result)) as *mut c_void
}

fn qs_result_err(err: *mut c_void) -> *mut c_void {
    let result = QsResult {
        is_ok: false,
        ok: std::ptr::null_mut(),
        err,
    };
    Box::into_raw(Box::new(result)) as *mut c_void
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
    if map.is_null() || key.is_null() || val.is_null() {
        return;
    }
    unsafe {
        let m = &mut *(map as *mut KvMap);
        // Key is stored as owned CString; lookups borrow as &CStr to avoid reallocation
        let Ok(k) = CString::new(CStr::from_ptr(key).to_bytes()) else {
            return;
        };
        m.inner.insert(k, val);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_obj_get_str(map: *mut c_void, key: *const c_char) -> *mut c_void {
    if map.is_null() || key.is_null() {
        return std::ptr::null_mut();
    }
    unsafe {
        let m = &mut *(map as *mut KvMap);
        let k = CStr::from_ptr(key);
        match m.inner.get(k) {
            Some(ptr) => *ptr,
            None => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_str_replace(
    haystack: *const c_char,
    needle: *const c_char,
    replacement: *const c_char,
) -> *mut c_char {
    unsafe {
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
            return arena_alloc_cstring(hay_bytes);
        }

        let needle_len = needle_bytes.len();
        let mut result = Vec::with_capacity(hay_bytes.len());
        let mut index = 0;
        let hay_len = hay_bytes.len();
        while index < hay_len {
            if index + needle_len <= hay_len
                && &hay_bytes[index..index + needle_len] == needle_bytes
            {
                result.extend_from_slice(replacement_bytes);
                index += needle_len;
            } else {
                result.push(hay_bytes[index]);
                index += 1;
            }
        }

        arena_alloc_cstring(&result)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_option_unwrap(optional: *mut c_void, line: f64) -> *mut c_void {
    if optional.is_null() {
        eprintln!("[Line {line}] Optional Value was None, Exiting...");
        std::process::exit(70);
    }
    optional
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_result_unwrap(optional: *const QsResult, line: f64) -> *mut c_void {
    if optional.is_null() {
        eprintln!("Result Value was none, exiting...");
        std::process::exit(70);
    }
    let optional = unsafe { *optional };
    if optional.is_ok {
        return optional.ok;
    } else {
        eprint!("[Line {line}] Result Value was Err(");
        unsafe {
            printf("%s), Exiting...\0".as_ptr() as *const i8, optional.err);
        }
        std::process::exit(70);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_str_split(
    haystack: *const c_char,
    delimiter: *const c_char,
) -> *mut c_void {
    unsafe {
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
            let ptr = arena_alloc_cstring(&seg) as *mut c_void;
            c_strings.push(ptr);
        }

        let slots = c_strings.len() + 1;
        let total_bytes = slots * std::mem::size_of::<*mut c_void>();
        let buffer = alloc_in_arena(total_bytes, std::mem::align_of::<*mut c_void>());
        if buffer.is_null() {
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
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_list_join(list: *mut c_void, separator: *const c_char) -> *mut c_char {
    unsafe {
        let empty_cstring = || arena_alloc_cstring(&[]);

        if list.is_null() {
            return empty_cstring();
        }

        let len_ptr = list.cast::<f64>();
        let length = (*len_ptr).round() as usize;

        if length == 0 {
            return empty_cstring();
        }

        let sep_bytes = if separator.is_null() {
            &[][..]
        } else {
            CStr::from_ptr(separator).to_bytes()
        };

        let data_ptr = list.cast::<*mut c_void>().add(1);
        let mut total_len = sep_bytes.len() * length.saturating_sub(1);
        let mut elements: Vec<*const c_char> = Vec::with_capacity(length);

        for idx in 0..length {
            let raw = *data_ptr.add(idx) as *const c_char;
            if raw.is_null() {
                elements.push(std::ptr::null());
                continue;
            }
            let bytes = CStr::from_ptr(raw).to_bytes();
            total_len += bytes.len();
            elements.push(raw);
        }

        let mut output = Vec::with_capacity(total_len);
        for (index, ptr) in elements.iter().enumerate() {
            if !ptr.is_null() {
                output.extend_from_slice(CStr::from_ptr(*ptr).to_bytes());
            }
            if index + 1 != length {
                output.extend_from_slice(sep_bytes);
            }
        }

        arena_alloc_cstring(&output)
    }
}
use hyper::body::Body;
use inkwell::basic_block::BasicBlock;
use inkwell::targets::InitializationConfig;
use inkwell::types::BasicTypeEnum;

use std::alloc::{Layout, alloc, dealloc};
use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt::{Debug, Display, Formatter};
use std::fs;
use std::mem;
use std::process::Command;
use std::ptr::{self, NonNull};

use std::convert::Infallible;
use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::future::Future;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

// Hyper (async HTTP server)
use hyper::service::{make_service_fn, service_fn};
use hyper::{Request as HyperRequest, Response as HyperResponse, StatusCode};
use serde_json::{self, Value as JsonValue};

// ───── High-Performance HTTP Runtime (Actix-style) ─────

// Unique ID generator for anonymous functions to avoid name collisions
static INLINE_FN_COUNTER: AtomicUsize = AtomicUsize::new(0);
static SERVER_RUNNING: AtomicBool = AtomicBool::new(false);
static LLVM_INIT: OnceLock<()> = OnceLock::new();

unsafe fn cstr_to_string(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(ptr).to_string_lossy().to_string() }
}

unsafe fn cstr_to_option_string(ptr: *const c_char) -> Option<String> {
    unsafe {
        if ptr.is_null() {
            None
        } else {
            Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
        }
    }
}

fn cstr_to_path<'a>(ptr: *const c_char) -> Option<Cow<'a, Path>> {
    if ptr.is_null() {
        return None;
    }

    unsafe {
        let cstr = CStr::from_ptr(ptr);
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let os = std::ffi::OsStr::from_bytes(cstr.to_bytes());
            return Some(Cow::Borrowed(Path::new(os)));
        }

        #[cfg(not(unix))]
        {
            let owned = cstr.to_string_lossy().to_string();
            return Some(Cow::Owned(PathBuf::from(owned)));
        }
    }
}

// Global Tokio runtime for blocking FFI helpers when no runtime is active
static GLOBAL_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
// Dedicated server runtime to keep the HTTP server truly async and alive
static SERVER_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn block_on_in_runtime<F: Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(move || handle.block_on(fut))
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
        inkwell::targets::Target::initialize_native(&InitializationConfig::default())
            .expect("Failed to start the QuickScript runner");
        unsafe {
            LLVMLinkInInterpreter();
            LLVMLinkInMCJIT();
        }
    });
}

#[cfg(target_os = "macos")]
fn detect_macos_deployment_target() -> Option<String> {
    if let Ok(val) = env::var("MACOSX_DEPLOYMENT_TARGET") {
        if !val.trim().is_empty() {
            return Some(val);
        }
    }

    if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
        if output.status.success() {
            if let Ok(text) = String::from_utf8(output.stdout) {
                let mut parts = text.trim().split('.').take(2).collect::<Vec<_>>();
                if parts.len() == 1 {
                    parts.push("0");
                }
                return Some(parts.join("."));
            }
        }
    }

    None
}

#[derive(Clone, Debug)]
struct EnumVariantSchema {
    name: String,
    payload: Vec<SchemaType>,
}

#[derive(Clone, Debug)]
enum SchemaType {
    Num,
    Str,
    Bool,
    List(Box<SchemaType>),
    Option(Box<SchemaType>),
    Result(Box<SchemaType>, Box<SchemaType>),
    Custom(String),
    Enum(Vec<EnumVariantSchema>),
}

#[derive(Clone, Debug)]
struct StructFieldSchema {
    name: String,
    schema: SchemaType,
}

#[derive(Clone, Debug)]
struct StructDescriptor {
    canonical_name: String,
    structural_signature: String,
    fields: Vec<StructFieldSchema>,
}

static STRUCT_REGISTRY: OnceLock<Mutex<HashMap<String, StructDescriptor>>> = OnceLock::new();
static STRUCT_SIGNATURES: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
static ENUM_REGISTRY: OnceLock<Mutex<HashMap<String, EnumDescriptor>>> = OnceLock::new();
static ENUM_SIGNATURES: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn struct_registry() -> &'static Mutex<HashMap<String, StructDescriptor>> {
    STRUCT_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn signature_registry() -> &'static Mutex<HashMap<String, String>> {
    STRUCT_SIGNATURES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn enum_registry() -> &'static Mutex<HashMap<String, EnumDescriptor>> {
    ENUM_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn enum_signature_registry() -> &'static Mutex<HashMap<String, String>> {
    ENUM_SIGNATURES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn parse_schema(signature: &str) -> Result<SchemaType, String> {
    let trimmed = signature.trim();
    if trimmed.is_empty() {
        return Err("Empty type signature".to_string());
    }

    if trimmed == "Num" {
        return Ok(SchemaType::Num);
    }
    if trimmed == "Str" {
        return Ok(SchemaType::Str);
    }
    if trimmed == "Bool" {
        return Ok(SchemaType::Bool);
    }

    if trimmed.starts_with("Maybe(") {
        return Err(
            "Maybe(...) signatures are no longer supported; use Option(...) instead.".to_string(),
        );
    }

    if let Some(inner) = trimmed.strip_prefix("Option(") {
        if let Some(inner) = inner.strip_suffix(')') {
            let parsed = parse_schema(inner)?;
            return Ok(SchemaType::Option(Box::new(parsed)));
        }
        return Err(format!("Malformed Option signature: {trimmed}"));
    }

    if let Some(inner) = trimmed.strip_prefix("List(") {
        if let Some(inner) = inner.strip_suffix(')') {
            let parsed = parse_schema(inner)?;
            return Ok(SchemaType::List(Box::new(parsed)));
        }
        return Err(format!("Malformed List signature: {trimmed}"));
    }

    if let Some(inner) = trimmed.strip_prefix("Result(") {
        if let Some(inner) = inner.strip_suffix(')') {
            let mut depth = 0;
            let mut split_idx = None;
            for (idx, ch) in inner.char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    ',' if depth == 0 => {
                        split_idx = Some(idx);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(idx) = split_idx {
                let (ok_part, err_part) = inner.split_at(idx);
                let ok_part = ok_part.trim();
                let err_part = err_part.trim_start_matches(',').trim();
                let ok_ty = parse_schema(ok_part)?;
                let err_ty = parse_schema(err_part)?;
                return Ok(SchemaType::Result(Box::new(ok_ty), Box::new(err_ty)));
            }
        }
        return Err(format!("Malformed Result signature: {trimmed}"));
    }

    if let Some(enum_body) = trimmed.strip_prefix("Enum{") {
        if let Some(inner) = enum_body.strip_suffix('}') {
            let mut variants = Vec::new();
            for variant_chunk in inner.split('|') {
                let variant_chunk = variant_chunk.trim();
                if variant_chunk.is_empty() {
                    continue;
                }
                if let Some(payload_start) = variant_chunk.find('(') {
                    let (name_part, rest) = variant_chunk.split_at(payload_start);
                    let name = name_part.trim().to_string();
                    let payload_part = rest.trim_start_matches('(').trim_end_matches(')');
                    let mut payload = Vec::new();
                    if !payload_part.is_empty() {
                        let mut depth = 0;
                        let mut start = 0;
                        for (idx, ch) in payload_part.char_indices() {
                            match ch {
                                '(' => depth += 1,
                                ')' => depth -= 1,
                                ',' if depth == 0 => {
                                    let piece = payload_part[start..idx].trim();
                                    if !piece.is_empty() {
                                        payload.push(parse_schema(piece)?);
                                    }
                                    start = idx + 1;
                                }
                                _ => {}
                            }
                        }
                        let tail = payload_part[start..].trim();
                        if !tail.is_empty() {
                            payload.push(parse_schema(tail)?);
                        }
                    }
                    variants.push(EnumVariantSchema { name, payload });
                } else {
                    variants.push(EnumVariantSchema {
                        name: variant_chunk.to_string(),
                        payload: Vec::new(),
                    });
                }
            }
            return Ok(SchemaType::Enum(variants));
        }
        return Err(format!("Malformed Enum signature: {trimmed}"));
    }

    Ok(SchemaType::Custom(trimmed.to_string()))
}

fn resolve_descriptor_name(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    if struct_registry().lock().ok()?.contains_key(raw) {
        return Some(raw.to_string());
    }
    if enum_registry().lock().ok()?.contains_key(raw) {
        return Some(raw.to_string());
    }
    if let Some(name) = signature_registry()
        .lock()
        .ok()
        .and_then(|map| map.get(raw).cloned())
    {
        return Some(name);
    }
    enum_signature_registry()
        .lock()
        .ok()
        .and_then(|map| map.get(raw).cloned())
}

fn find_descriptor(name: &str) -> Option<StructDescriptor> {
    let canonical = resolve_descriptor_name(name)?;
    struct_registry()
        .lock()
        .ok()
        .and_then(|map| map.get(&canonical).cloned())
}

#[derive(Clone, Debug)]
struct EnumDescriptor {
    canonical_name: String,
    structural_signature: String,
    variants: Vec<EnumVariantSchema>,
}

fn find_enum_descriptor(name: &str) -> Option<EnumDescriptor> {
    let canonical = resolve_descriptor_name(name)?;
    enum_registry()
        .lock()
        .ok()
        .and_then(|map| map.get(&canonical).cloned())
}

#[derive(Clone)]
pub struct JsonHandle {
    value: JsonValue,
}

enum ValueRepr {
    Float(f64),
    Bool(bool),
    Pointer(*mut c_void),
}

unsafe fn store_value(slot_ptr: *mut u8, repr: ValueRepr) {
    unsafe {
        match repr {
            ValueRepr::Float(f) => (slot_ptr as *mut f64).write(f),
            ValueRepr::Bool(b) => (slot_ptr as *mut u64).write(if b { 1 } else { 0 }),
            ValueRepr::Pointer(ptr) => (slot_ptr as *mut *mut c_void).write(ptr),
        }
    }
}

fn wrap_pointer_from_repr(repr: ValueRepr) -> Result<*mut c_void, String> {
    match repr {
        ValueRepr::Pointer(ptr) => Ok(ptr),
        ValueRepr::Float(_) | ValueRepr::Bool(_) => {
            Err("Option values for primitive numbers or booleans are not yet supported".to_string())
        }
    }
}

fn coerce_json_to_value(schema: &SchemaType, value: &JsonValue) -> Result<ValueRepr, String> {
    match schema {
        SchemaType::Num => value
            .as_f64()
            .ok_or_else(|| format!("Expected number, found {value}"))
            .map(ValueRepr::Float),
        SchemaType::Str => value
            .as_str()
            .ok_or_else(|| format!("Expected string, found {value}"))
            .and_then(|s| {
                let bytes = s.as_bytes();
                if bytes.contains(&0) {
                    Err(format!(
                        "String value for JSON field contains embedded null: {s:?}"
                    ))
                } else {
                    let ptr = arena_alloc_cstring(bytes) as *mut c_void;
                    if ptr.is_null() {
                        Err("Failed to allocate string in arena".to_string())
                    } else {
                        Ok(ValueRepr::Pointer(ptr))
                    }
                }
            }),
        SchemaType::Bool => value
            .as_bool()
            .ok_or_else(|| format!("Expected boolean, found {value}"))
            .map(ValueRepr::Bool),
        SchemaType::Custom(name) => {
            let descriptor = find_descriptor(name).ok_or_else(|| {
                format!("JSON conversion requires registered type '{name}', but none was found")
            })?;
            let ptr = build_struct_from_json_value(&descriptor, value)?;
            Ok(ValueRepr::Pointer(ptr))
        }
        SchemaType::List(inner) => {
            let array = value
                .as_array()
                .ok_or_else(|| format!("Expected array, found {value}"))?;
            let ptr = build_list_from_json(inner, array)?;
            Ok(ValueRepr::Pointer(ptr))
        }
        SchemaType::Option(_) => {
            Err("Internal error: Option types should be handled by caller".to_string())
        }
        SchemaType::Result(_, _) => {
            Err("Result schemas are not yet supported in JSON conversion".to_string())
        }
        SchemaType::Enum(variants) => {
            let descriptor = EnumDescriptor {
                canonical_name: "<inline>".to_string(),
                structural_signature: String::new(),
                variants: variants.clone(),
            };
            let ptr = build_enum_from_json_value(&descriptor, value)?;
            Ok(ValueRepr::Pointer(ptr))
        }
    }
}

fn build_list_from_json(inner: &SchemaType, elements: &[JsonValue]) -> Result<*mut c_void, String> {
    let total_slots = elements.len() + 1;
    let total_bytes = total_slots
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or_else(|| "List size overflow".to_string())?;
    let buffer = alloc_in_arena(total_bytes, std::mem::align_of::<u64>());
    if buffer.is_null() {
        return Err("Failed to allocate memory for list".to_string());
    }

    unsafe {
        (buffer as *mut f64).write(elements.len() as f64);
    }

    for (index, element) in elements.iter().enumerate() {
        let slot_ptr = unsafe { (buffer as *mut u8).add((index + 1) * std::mem::size_of::<u64>()) };

        let repr = match inner {
            SchemaType::Option(inner_schema) => {
                if element.is_null() {
                    ValueRepr::Pointer(std::ptr::null_mut())
                } else {
                    let converted = coerce_json_to_value(inner_schema.as_ref(), element)?;
                    let ptr = wrap_pointer_from_repr(converted)?;
                    ValueRepr::Pointer(ptr)
                }
            }
            other => coerce_json_to_value(other, element)?,
        };

        unsafe { store_value(slot_ptr, repr) };
    }

    Ok(buffer)
}

fn build_struct_from_json_value(
    descriptor: &StructDescriptor,
    json_value: &JsonValue,
) -> Result<*mut c_void, String> {
    let obj = json_value.as_object().ok_or_else(|| {
        format!(
            "Expected JSON object while constructing '{}'",
            descriptor.canonical_name
        )
    })?;

    let field_count = descriptor.fields.len();
    let total_bytes = field_count
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or_else(|| "Struct size overflow".to_string())?;
    let buffer = alloc_in_arena(total_bytes, std::mem::align_of::<u64>());
    if buffer.is_null() {
        return Err(format!(
            "Failed to allocate memory while constructing '{}' from JSON",
            descriptor.canonical_name
        ));
    }

    for (index, field) in descriptor.fields.iter().enumerate() {
        let slot_ptr = unsafe { (buffer as *mut u8).add(index * std::mem::size_of::<u64>()) };

        match &field.schema {
            SchemaType::Option(inner) => {
                let maybe_value = obj.get(&field.name);
                let repr = if let Some(value) = maybe_value {
                    if value.is_null() {
                        ValueRepr::Pointer(std::ptr::null_mut())
                    } else {
                        let converted = coerce_json_to_value(inner, value)?;
                        let ptr = wrap_pointer_from_repr(converted)?;
                        ValueRepr::Pointer(ptr)
                    }
                } else {
                    ValueRepr::Pointer(std::ptr::null_mut())
                };
                unsafe { store_value(slot_ptr, repr) };
            }
            schema => {
                let value = obj.get(&field.name).ok_or_else(|| {
                    format!(
                        "Missing field '{}' while constructing '{}' from JSON",
                        field.name, descriptor.canonical_name
                    )
                })?;
                if value.is_null() {
                    return Err(format!(
                        "Field '{}' cannot be null when constructing '{}'",
                        field.name, descriptor.canonical_name
                    ));
                }
                let repr = coerce_json_to_value(schema, value)?;
                unsafe { store_value(slot_ptr, repr) };
            }
        }
    }

    Ok(buffer)
}

fn build_enum_from_json_value(
    descriptor: &EnumDescriptor,
    json_value: &JsonValue,
) -> Result<*mut c_void, String> {
    let obj = json_value.as_object().ok_or_else(|| {
        format!(
            "Expected JSON object while constructing enum '{}'",
            descriptor.canonical_name
        )
    })?;

    let variant_name = obj
        .get("variant")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Enum JSON must include a string 'variant' field".to_string())?;

    let (variant_index, variant_schema) = descriptor
        .variants
        .iter()
        .enumerate()
        .find(|(_, v)| v.name == variant_name)
        .ok_or_else(|| {
            format!(
                "Unknown variant '{}' for enum '{}'",
                variant_name, descriptor.canonical_name
            )
        })?;

    let payload_json = obj.get("value");
    let payload_values: Vec<JsonValue> = if variant_schema.payload.len() <= 1 {
        match (variant_schema.payload.first(), payload_json) {
            (None, _) => Vec::new(),
            (Some(_), Some(value)) => vec![value.clone()],
            (Some(_), None) => {
                return Err(format!(
                    "Variant '{}' expects payload but 'value' was missing",
                    variant_schema.name
                ));
            }
        }
    } else {
        let Some(JsonValue::Array(arr)) = payload_json else {
            return Err(format!(
                "Variant '{}' expects an array 'value' with {} entries",
                variant_schema.name,
                variant_schema.payload.len()
            ));
        };
        arr.clone()
    };

    if payload_values.len() != variant_schema.payload.len() {
        return Err(format!(
            "Variant '{}' expects {} payload item(s); got {}",
            variant_schema.name,
            variant_schema.payload.len(),
            payload_values.len()
        ));
    }

    let slot_bytes = std::mem::size_of::<u64>();
    let total_slots = variant_schema.payload.len() + 1;
    let total_bytes = total_slots
        .checked_mul(slot_bytes)
        .ok_or_else(|| "Enum size overflow".to_string())?;
    let buffer = alloc_in_arena(total_bytes, std::mem::align_of::<u64>());
    if buffer.is_null() {
        return Err(format!(
            "Failed to allocate memory while constructing enum '{}'",
            descriptor.canonical_name
        ));
    }

    unsafe {
        (buffer as *mut u64).write(variant_index as u64);
    }

    for (idx, (schema, value)) in variant_schema
        .payload
        .iter()
        .zip(payload_values.iter())
        .enumerate()
    {
        let slot_ptr = unsafe { (buffer as *mut u8).add((idx + 1) * slot_bytes) };
        let repr = coerce_json_to_value(schema, value)?;
        unsafe { store_value(slot_ptr, repr) };
    }

    Ok(buffer)
}

fn read_field_value(schema: &SchemaType, slot_ptr: *mut u8) -> JsonValue {
    match schema {
        SchemaType::Num => unsafe { JsonValue::from(*(slot_ptr as *mut f64)) },
        SchemaType::Str => {
            let ptr = unsafe { *(slot_ptr as *mut *mut c_void) } as *mut c_char;
            if ptr.is_null() {
                JsonValue::Null
            } else {
                unsafe { JsonValue::String(CStr::from_ptr(ptr).to_string_lossy().into_owned()) }
            }
        }
        SchemaType::Bool => {
            let raw = unsafe { *(slot_ptr as *mut u64) };
            JsonValue::Bool(raw != 0)
        }
        SchemaType::Custom(name) => {
            let ptr = unsafe { *(slot_ptr as *mut *mut c_void) };
            if ptr.is_null() {
                JsonValue::Null
            } else if let Some(descriptor) = find_descriptor(name) {
                struct_to_json_value(&descriptor, ptr)
            } else {
                JsonValue::Null
            }
        }
        SchemaType::List(inner) => {
            let ptr = unsafe { *(slot_ptr as *mut *mut c_void) };
            if ptr.is_null() {
                return JsonValue::Null;
            }
            let length = unsafe { *(ptr as *mut f64) } as usize;
            let mut items = Vec::with_capacity(length);
            for idx in 0..length {
                let elem_ptr =
                    unsafe { (ptr as *mut u8).add((idx + 1) * std::mem::size_of::<u64>()) };
                let value = match inner.as_ref() {
                    SchemaType::Option(inner_schema) => {
                        let raw = unsafe { *(elem_ptr as *mut *mut c_void) };
                        if raw.is_null() {
                            JsonValue::Null
                        } else {
                            read_field_value(inner_schema, raw as *mut u8)
                        }
                    }
                    other => read_field_value(other, elem_ptr),
                };
                items.push(value);
            }
            JsonValue::Array(items)
        }
        SchemaType::Option(inner) => {
            let ptr = unsafe { *(slot_ptr as *mut *mut c_void) };
            if ptr.is_null() {
                JsonValue::Null
            } else {
                read_field_value(inner, ptr as *mut u8)
            }
        }
        SchemaType::Result(_, _) => JsonValue::Null,
        SchemaType::Enum(variants) => {
            let ptr = unsafe { *(slot_ptr as *mut *mut c_void) };
            if ptr.is_null() {
                return JsonValue::Null;
            }
            let tag = unsafe { *(ptr as *mut u64) } as usize;
            let mut obj = serde_json::Map::new();
            if let Some(variant) = variants.get(tag) {
                obj.insert(
                    "variant".to_string(),
                    JsonValue::String(variant.name.clone()),
                );
                if !variant.payload.is_empty() {
                    let mut values = Vec::new();
                    for (idx, payload_schema) in variant.payload.iter().enumerate() {
                        let slot =
                            unsafe { (ptr as *mut u8).add((idx + 1) * std::mem::size_of::<u64>()) };
                        values.push(read_field_value(payload_schema, slot));
                    }
                    if variant.payload.len() == 1 {
                        obj.insert("value".to_string(), values.into_iter().next().unwrap());
                    } else {
                        obj.insert("value".to_string(), JsonValue::Array(values));
                    }
                }
            }
            JsonValue::Object(obj)
        }
    }
}

fn struct_to_json_value(descriptor: &StructDescriptor, ptr: *mut c_void) -> JsonValue {
    if ptr.is_null() {
        return JsonValue::Null;
    }
    let mut map = serde_json::Map::with_capacity(descriptor.fields.len());
    for (index, field) in descriptor.fields.iter().enumerate() {
        let slot_ptr = unsafe { (ptr as *mut u8).add(index * std::mem::size_of::<u64>()) };
        let value = read_field_value(&field.schema, slot_ptr);
        map.insert(field.name.clone(), value);
    }
    JsonValue::Object(map)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_register_struct_descriptor(
    canonical_name: *const c_char,
    structural_signature: *const c_char,
    field_count: usize,
    field_names: *const *const c_char,
    field_types: *const *const c_char,
) {
    unsafe {
        if canonical_name.is_null() || structural_signature.is_null() {
            return;
        }

        let name = CStr::from_ptr(canonical_name)
            .to_string_lossy()
            .into_owned();
        let signature = CStr::from_ptr(structural_signature)
            .to_string_lossy()
            .into_owned();

        let mut fields = Vec::with_capacity(field_count);
        for idx in 0..field_count {
            let name_ptr = *field_names.add(idx);
            let ty_ptr = *field_types.add(idx);
            if name_ptr.is_null() || ty_ptr.is_null() {
                continue;
            }
            let field_name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
            let ty_sig = CStr::from_ptr(ty_ptr).to_string_lossy().into_owned();

            match parse_schema(&ty_sig) {
                Ok(schema) => fields.push(StructFieldSchema {
                    name: field_name,
                    schema,
                }),
                Err(err) => eprintln!(
                    "Failed to register JSON schema for field '{field_name}' on '{name}': {err}"
                ),
            }
        }

        if let Ok(mut registry) = struct_registry().lock() {
            registry.insert(
                name.clone(),
                StructDescriptor {
                    canonical_name: name.clone(),
                    structural_signature: signature.clone(),
                    fields,
                },
            );
        }
        if let Ok(mut signatures) = signature_registry().lock() {
            signatures.insert(signature, name);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_register_enum_variant(
    canonical_name: *const c_char,
    structural_signature: *const c_char,
    variant_name: *const c_char,
    payload_count: usize,
    payload_types: *const *const c_char,
) {
    unsafe {
        if canonical_name.is_null() || structural_signature.is_null() || variant_name.is_null() {
            return;
        }

        let canonical = CStr::from_ptr(canonical_name)
            .to_string_lossy()
            .into_owned();
        let structural = CStr::from_ptr(structural_signature)
            .to_string_lossy()
            .into_owned();
        let vname = CStr::from_ptr(variant_name).to_string_lossy().into_owned();

        let mut payload = Vec::with_capacity(payload_count);
        for idx in 0..payload_count {
            let ty_ptr = *payload_types.add(idx);
            if ty_ptr.is_null() {
                continue;
            }
            let ty_sig = CStr::from_ptr(ty_ptr).to_string_lossy().into_owned();
            if let Ok(parsed) = parse_schema(&ty_sig) {
                payload.push(parsed);
            }
        }

        if let Ok(mut registry) = enum_registry().lock() {
            let entry = registry
                .entry(canonical.clone())
                .or_insert_with(|| EnumDescriptor {
                    canonical_name: canonical.clone(),
                    structural_signature: structural.clone(),
                    variants: Vec::new(),
                });
            entry.variants.push(EnumVariantSchema {
                name: vname.clone(),
                payload,
            });
        }
        if let Ok(mut signatures) = enum_signature_registry().lock() {
            signatures.insert(structural, canonical);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_struct_from_json(
    canonical_name: *const c_char,
    json_payload: *const c_char,
) -> *mut c_void {
    unsafe {
        if canonical_name.is_null() || json_payload.is_null() {
            return std::ptr::null_mut();
        }

        let type_name = CStr::from_ptr(canonical_name)
            .to_string_lossy()
            .into_owned();
        let payload = CStr::from_ptr(json_payload).to_string_lossy().into_owned();

        let descriptor = match find_descriptor(&type_name) {
            Some(desc) => desc,
            None => {
                // eprintln!(
                //     "Cannot deserialize JSON for '{type_name}': type descriptor is not registered"
                // );
                return std::ptr::null_mut();
            }
        };

        let parsed: JsonValue = match serde_json::from_str(&payload) {
            Ok(v) => v,
            Err(_err) => {
                //  eprintln!("Failed to parse JSON payload for '{type_name}': {err}");
                return std::ptr::null_mut();
            }
        };

        match build_struct_from_json_value(&descriptor, &parsed) {
            Ok(ptr) => ptr,
            Err(_err) => {
                //            eprintln!("Failed to convert JSON into '{type_name}': {err}");
                std::ptr::null_mut()
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_enum_from_json(
    canonical_name: *const c_char,
    json_payload: *const c_char,
) -> *mut c_void {
    unsafe {
        if canonical_name.is_null() || json_payload.is_null() {
            return std::ptr::null_mut();
        }

        let type_name = CStr::from_ptr(canonical_name)
            .to_string_lossy()
            .into_owned();
        let payload = CStr::from_ptr(json_payload).to_string_lossy().into_owned();

        let descriptor = match find_enum_descriptor(&type_name) {
            Some(desc) => desc,
            None => {
                return std::ptr::null_mut();
            }
        };

        let parsed: JsonValue = match serde_json::from_str(&payload) {
            Ok(v) => v,
            Err(_) => {
                return std::ptr::null_mut();
            }
        };

        match build_enum_from_json_value(&descriptor, &parsed) {
            Ok(ptr) => ptr,
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_struct_to_json(
    canonical_name: *const c_char,
    struct_ptr: *mut c_void,
) -> *mut c_char {
    unsafe {
        if canonical_name.is_null() {
            return std::ptr::null_mut();
        }

        let type_name = CStr::from_ptr(canonical_name)
            .to_string_lossy()
            .into_owned();

        let descriptor = match find_descriptor(&type_name) {
            Some(desc) => desc,
            None => {
                eprintln!(
                    "Cannot serialize '{type_name}' to JSON: type descriptor is not registered"
                );
                return std::ptr::null_mut();
            }
        };

        let json_value = struct_to_json_value(&descriptor, struct_ptr);
        match serde_json::to_string(&json_value) {
            Ok(rendered) => {
                let bytes = rendered.into_bytes();
                if bytes.contains(&0) {
                    std::ptr::null_mut()
                } else {
                    arena_alloc_cstring(&bytes)
                }
            }
            Err(err) => {
                eprintln!("Failed to render JSON for '{type_name}': {err}");
                std::ptr::null_mut()
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_json_parse(source: *const c_char) -> *mut c_void {
    unsafe {
        if source.is_null() {
            let msg = arena_alloc_cstring(b"io.json received null input");
            return qs_result_err(msg as *mut c_void);
        }
        let text = CStr::from_ptr(source).to_str().unwrap_or_default();
        let parsed = match serde_json::from_str::<JsonValue>(&text) {
            Ok(value) => value,
            Err(err) => {
                let err_text = err.to_string();
                let msg = if err_text.as_bytes().contains(&0) {
                    arena_alloc_cstring(b"io.json parse error")
                } else {
                    arena_alloc_cstring(err_text.as_bytes())
                };
                return qs_result_err(msg as *mut c_void);
            }
        };

        let JsonValue::Object(map) = parsed else {
            let msg = arena_alloc_cstring(b"io.json expects an object at the top level");
            return qs_result_err(msg as *mut c_void);
        };

        let obj_ptr = qs_obj_new();
        for (key, value) in map {
            let handle_raw = Box::into_raw(Box::new(JsonHandle { value }));
            let Ok(key_c) = std::ffi::CString::new(key) else {
                let _ = Box::from_raw(handle_raw);
                continue;
            };
            qs_obj_insert_str(obj_ptr, key_c.as_ptr(), handle_raw as *mut c_void);
        }

        qs_result_ok(obj_ptr)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn qs_json_stringify(handle: *mut JsonHandle) -> *mut c_char {
    match NonNull::new(handle) {
        Some(handle) => unsafe {
            match serde_json::to_string(&handle.as_ref().value) {
                Ok(rendered) => {
                    let bytes = rendered.into_bytes();
                    if bytes.contains(&0) {
                        std::ptr::null_mut()
                    } else {
                        arena_alloc_cstring(&bytes)
                    }
                }
                Err(err) => {
                    eprintln!("Failed to stringify JSON value: {err}");
                    std::ptr::null_mut()
                }
            }
        },
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn qs_json_is_null(handle: *mut JsonHandle) -> bool {
    unsafe {
        match NonNull::new(handle) {
            Some(nn) => matches!(nn.as_ref().value, JsonValue::Null),
            None => true,
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn qs_json_len(handle: *mut JsonHandle) -> i64 {
    unsafe {
        match NonNull::new(handle) {
            Some(handle) => match &handle.as_ref().value {
                JsonValue::Array(items) => items.len() as i64,
                JsonValue::Object(map) => map.len() as i64,
                _ => 0,
            },
            None => 0,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_json_get(
    handle: *mut JsonHandle,
    key: *const c_char,
) -> *mut JsonHandle {
    unsafe {
        if handle.is_null() || key.is_null() {
            return std::ptr::null_mut();
        }
        let Some(object) = (*handle).value.as_object() else {
            return std::ptr::null_mut();
        };
        let key_str = CStr::from_ptr(key).to_string_lossy();
        match object.get(key_str.as_ref()) {
            Some(value) => Box::into_raw(Box::new(JsonHandle {
                value: value.clone(),
            })),
            None => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_json_index(handle: *mut JsonHandle, index: usize) -> *mut JsonHandle {
    unsafe {
        if handle.is_null() {
            return std::ptr::null_mut();
        }
        let Some(array) = (*handle).value.as_array() else {
            return std::ptr::null_mut();
        };
        array
            .get(index)
            .cloned()
            .map(|value| Box::into_raw(Box::new(JsonHandle { value })))
            .unwrap_or_else(std::ptr::null_mut)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_json_str(handle: *mut JsonHandle) -> *mut c_char {
    unsafe {
        if handle.is_null() {
            return std::ptr::null_mut();
        }
        match (*handle).value.as_str() {
            Some(text) => {
                let bytes = text.as_bytes();
                if bytes.contains(&0) {
                    std::ptr::null_mut()
                } else {
                    arena_alloc_cstring(bytes)
                }
            }
            None => std::ptr::null_mut(),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_create(capacity: usize) -> *mut Arena {
    unsafe {
        let cap = capacity.max(1024);
        let ptr = Box::into_raw(Box::new(Arena::new(cap)));
        GLOBAL_ARENA_PTR = ptr;
        ptr
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_alloc(arena: *mut Arena, size: usize, align: usize) -> *mut u8 {
    unsafe {
        let Some(mut arena) = NonNull::new(arena) else {
            return std::ptr::null_mut();
        };

        let layout = match Layout::from_size_align(size, align) {
            Ok(l) => l,
            Err(_) => return std::ptr::null_mut(),
        };

        arena
            .as_mut()
            .alloc(layout)
            .map(|p| p.as_ptr())
            .unwrap_or(std::ptr::null_mut())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_free(arena: *mut Arena, ptr: *mut u8) {
    unsafe {
        if arena.is_null() || ptr.is_null() {
            return;
        }
        if let Some(mut arena) = NonNull::new(arena) {
            arena.as_mut().release_ref(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_mark(arena: *mut Arena) -> usize {
    unsafe { NonNull::new(arena).map(|a| a.as_ref().mark()).unwrap_or(0) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_release(arena: *mut Arena, mark: usize) {
    unsafe {
        if let Some(mut arena) = NonNull::new(arena) {
            arena.as_mut().release_from(mark);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_pin(arena: *mut Arena, ptr: *mut u8) {
    unsafe {
        if let Some(mut arena) = NonNull::new(arena) {
            arena.as_mut().retain(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_retain(arena: *mut Arena, ptr: *mut u8) {
    unsafe {
        if let Some(mut arena) = NonNull::new(arena) {
            arena.as_mut().retain(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_release_ref(arena: *mut Arena, ptr: *mut u8) {
    unsafe {
        if let Some(mut arena) = NonNull::new(arena) {
            arena.as_mut().release_ref(ptr);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn arena_destroy(arena: *mut Arena) {
    unsafe {
        if arena.is_null() {
            return;
        }
        let arena_box = Box::from_raw(arena);
        if ARENA_DEBUG_CHECKS.load(Ordering::Relaxed) {
            if let Some(leaked) = arena_box
                .allocations
                .iter()
                .find(|allocation| allocation.refs > 0)
            {
                panic!(
                    "Arena leak detected: ptr={:?} still has {} outstanding reference(s)",
                    leaked.ptr, leaked.refs
                );
            }
        }
        if GLOBAL_ARENA_PTR == arena {
            GLOBAL_ARENA_PTR = std::ptr::null_mut();
        }
        drop(arena_box);
    }
}

#[repr(C)]
pub struct RequestObject {
    method: *mut c_char,
    path: *mut c_char,
    query: *mut c_char,
    headers: *mut c_char,
    body: *mut c_char,
}

fn owned_string_to_c_ptr(value: String) -> *mut c_char {
    let bytes = value.into_bytes();
    if bytes.contains(&0) {
        panic!("Request field contains interior null byte");
    }
    arena_alloc_cstring(&bytes)
}

fn option_string_to_c_ptr(value: Option<String>) -> *mut c_char {
    value.map_or(std::ptr::null_mut(), owned_string_to_c_ptr)
}

impl RequestObject {
    fn from_owned_parts(
        method: Option<String>,
        path: Option<String>,
        query: Option<String>,
        headers: Option<String>,
        body: Option<String>,
    ) -> Self {
        Self {
            method: option_string_to_c_ptr(method),
            path: option_string_to_c_ptr(path),
            query: option_string_to_c_ptr(query),
            headers: option_string_to_c_ptr(headers),
            body: option_string_to_c_ptr(body),
        }
    }
}

impl Drop for RequestObject {
    fn drop(&mut self) {
        unsafe {
            free_c_string(self.method);
            self.method = std::ptr::null_mut();

            free_c_string(self.path);
            self.path = std::ptr::null_mut();

            free_c_string(self.query);
            self.query = std::ptr::null_mut();

            free_c_string(self.headers);
            self.headers = std::ptr::null_mut();

            free_c_string(self.body);
            self.body = std::ptr::null_mut();
        }
    }
}

// Response object for structured HTTP responses
#[repr(C)]
pub struct ResponseObject {
    status_code: i32,
    content_type: *mut c_char,
    body: *mut u8,
    body_len: usize,
    headers: *mut c_char,
    missing_file_path: *mut c_char,
}

fn leak_string_as_body(text: String) -> (*mut u8, usize) {
    leak_bytes_as_body(text.into_bytes())
}

fn leak_bytes_as_body(mut bytes: Vec<u8>) -> (*mut u8, usize) {
    if bytes.is_empty() {
        (std::ptr::null_mut(), 0)
    } else {
        let len = bytes.len();
        let ptr = bytes.as_mut_ptr();
        std::mem::forget(bytes);
        (ptr, len)
    }
}

unsafe fn free_body(ptr: *mut u8, len: usize) {
    unsafe {
        if !ptr.is_null() && len > 0 {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

unsafe fn free_c_string(_ptr: *mut c_char) {}

impl ResponseObject {
    unsafe fn take_body_bytes(&mut self) -> Vec<u8> {
        unsafe {
            let ptr = self.body;
            let len = self.body_len;
            self.body = std::ptr::null_mut();
            self.body_len = 0;
            if ptr.is_null() || len == 0 {
                Vec::new()
            } else {
                Vec::from_raw_parts(ptr, len, len)
            }
        }
    }

    unsafe fn take_owned_string(field: &mut *mut c_char) -> Option<String> {
        unsafe {
            if (*field).is_null() {
                None
            } else {
                let ptr = std::mem::replace(field, std::ptr::null_mut());
                let cstr = CStr::from_ptr(ptr);
                Some(cstr.to_string_lossy().into_owned())
            }
        }
    }
}

impl Drop for ResponseObject {
    fn drop(&mut self) {
        unsafe {
            free_c_string(self.content_type);
            self.content_type = std::ptr::null_mut();

            free_body(self.body, self.body_len);
            self.body = std::ptr::null_mut();
            self.body_len = 0;

            free_c_string(self.headers);
            self.headers = std::ptr::null_mut();

            free_c_string(self.missing_file_path);
            self.missing_file_path = std::ptr::null_mut();
        }
    }
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
    unsafe {
        let body_string = match cstr_to_option_string(body) {
            Some(text) if text.is_empty() => None,
            other => other,
        };
        let request = RequestObject::from_owned_parts(
            cstr_to_option_string(method),
            cstr_to_option_string(path),
            cstr_to_option_string(query),
            cstr_to_option_string(headers),
            body_string,
        );
        Box::into_raw(Box::new(request))
    }
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
    unsafe {
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
}

// Compatibility shim for compiler-expected symbol name
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_range_builder_to(
    buil: *mut RangeBuilder,
    tua: f64,
) -> *mut RangeBuilder {
    unsafe { range_builder_to(buil, tua) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_from(
    buil: *mut RangeBuilder,
    tua: f64,
) -> *mut RangeBuilder {
    unsafe {
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
}

// Compatibility shim for compiler-expected symbol name
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_range_builder_from(
    buil: *mut RangeBuilder,
    tua: f64,
) -> *mut RangeBuilder {
    unsafe { range_builder_from(buil, tua) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_step(
    buil: *mut RangeBuilder,
    tua: f64,
) -> *mut RangeBuilder {
    unsafe {
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
}

// Compatibility shim for compiler-expected symbol name
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_range_builder_step(
    buil: *mut RangeBuilder,
    tua: f64,
) -> *mut RangeBuilder {
    unsafe { range_builder_step(buil, tua) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_get_from(buil: *const RangeBuilder) -> f64 {
    unsafe {
        if buil.is_null() {
            return 0.0;
        }
        (*buil).from
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_get_to(buil: *const RangeBuilder) -> f64 {
    unsafe {
        if buil.is_null() {
            return 0.0;
        }
        (*buil).to
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn range_builder_get_step(buil: *const RangeBuilder) -> f64 {
    unsafe {
        if buil.is_null() {
            return 1.0;
        }
        let step = (*buil).step;
        if step == 0.0 { 1.0 } else { step }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_text(content: *const c_char) -> *mut ResponseObject {
    let content_bytes = if content.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr(content).to_bytes().to_owned() }
    };

    let (body_ptr, body_len) = leak_bytes_as_body(content_bytes);

    let response = Box::new(ResponseObject {
        status_code: 200,
        content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
        body: body_ptr,
        body_len,
        headers: arena_alloc_cstring(b""),
        missing_file_path: std::ptr::null_mut(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_json(content: *const c_char) -> *mut ResponseObject {
    let content_bytes = if content.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr(content).to_bytes().to_owned() }
    };

    let (body_ptr, body_len) = leak_bytes_as_body(content_bytes);

    let response = Box::new(ResponseObject {
        status_code: 200,
        content_type: arena_alloc_cstring(b"application/json; charset=utf-8"),
        body: body_ptr,
        body_len,
        headers: arena_alloc_cstring(b""),
        missing_file_path: std::ptr::null_mut(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_page(content: *const c_char) -> *mut ResponseObject {
    let content_bytes = if content.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr(content).to_bytes().to_owned() }
    };

    let (body_ptr, body_len) = leak_bytes_as_body(content_bytes);

    let response = Box::new(ResponseObject {
        status_code: 200,
        content_type: arena_alloc_cstring(b"text/html; charset=utf-8"),
        body: body_ptr,
        body_len,
        headers: arena_alloc_cstring(b""),
        missing_file_path: std::ptr::null_mut(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_error_text(
    status_code: i32,
    content: *const c_char,
) -> *mut ResponseObject {
    let content_bytes = if content.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr(content).to_bytes().to_owned() }
    };

    let (body_ptr, body_len) = leak_bytes_as_body(content_bytes);

    let response = Box::new(ResponseObject {
        status_code,
        content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
        body: body_ptr,
        body_len,
        headers: arena_alloc_cstring(b""),
        missing_file_path: std::ptr::null_mut(),
    });
    Box::into_raw(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_error_page(
    status_code: i32,
    content: *const c_char,
) -> *mut ResponseObject {
    let content_bytes = if content.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr(content).to_bytes().to_owned() }
    };

    let (body_ptr, body_len) = leak_bytes_as_body(content_bytes);

    let response = Box::new(ResponseObject {
        status_code,
        content_type: arena_alloc_cstring(b"text/html; charset=utf-8"),
        body: body_ptr,
        body_len,
        headers: arena_alloc_cstring(b""),
        missing_file_path: std::ptr::null_mut(),
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

    let (body_ptr, body_len) = leak_string_as_body(String::new());

    let header_bytes = headers.into_bytes();

    let response = Box::new(ResponseObject {
        status_code,
        content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
        body: body_ptr,
        body_len,
        headers: arena_cstring_from_bytes_checked(&header_bytes),
        missing_file_path: std::ptr::null_mut(),
    });
    Box::into_raw(response)
}

// Async file reading function for io.read() - now the default
#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_read_file(filename: *const c_char) -> *mut c_void {
    if filename.is_null() {
        let msg = arena_alloc_cstring(b"io.read received null filename");
        return qs_result_err(msg as *mut c_void);
    }

    let Some(path) = cstr_to_path(filename) else {
        let msg = arena_alloc_cstring(b"io.read received invalid filename");
        return qs_result_err(msg as *mut c_void);
    };

    let read_result = block_on_in_runtime(async { tokio::fs::read_to_string(path.as_ref()).await });

    match read_result {
        Ok(content) => {
            let bytes = content.into_bytes();
            let owned = arena_cstring_from_bytes_checked(&bytes);
            if owned.is_null() {
                let msg = arena_alloc_cstring(b"io.read failed");
                qs_result_err(msg as *mut c_void)
            } else {
                qs_result_ok(owned as *mut c_void)
            }
        }
        Err(err) => {
            let msg_text = err.to_string();
            let c_msg = arena_cstring_from_bytes_checked(msg_text.as_bytes());
            let c_msg = if c_msg.is_null() {
                arena_alloc_cstring(b"io.read failed")
            } else {
                c_msg
            };
            qs_result_err(c_msg as *mut c_void)
        }
    }
}

// Async file writing function for io.write() - now returns Result(Str, Str)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_write_file(
    filename: *const c_char,
    content: *const c_char,
) -> *mut c_void {
    if filename.is_null() || content.is_null() {
        let msg = arena_alloc_cstring(b"io.write received null pointer");
        return qs_result_err(msg as *mut c_void);
    }

    let Some(path) = cstr_to_path(filename) else {
        let msg = arena_alloc_cstring(b"io.write received invalid filename");
        return qs_result_err(msg as *mut c_void);
    };

    let content_bytes = unsafe { CStr::from_ptr(content).to_bytes() };

    match block_on_in_runtime(async { tokio::fs::write(path.as_ref(), content_bytes).await }) {
        Ok(_) => {
            let ok_msg = arena_alloc_cstring(b"");
            qs_result_ok(ok_msg as *mut c_void)
        }
        Err(err) => {
            let msg_text = err.to_string();
            let c_msg = arena_cstring_from_bytes_checked(msg_text.as_bytes());
            let c_msg = if c_msg.is_null() {
                arena_alloc_cstring(b"io.write failed")
            } else {
                c_msg
            };
            qs_result_err(c_msg as *mut c_void)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_panic(message: *const c_char) -> ! {
    unsafe {
        if message.is_null() {
            eprintln!("QuickScript panic");
        } else {
            let text = CStr::from_ptr(message).to_str().unwrap_or_default();
            eprintln!("QuickScript panic: {text}",);
        }
        std::process::exit(70);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_exit(code: f64) {
    let mut exit_code = code.round() as i32;
    if exit_code < 0 {
        exit_code = 0;
    }
    std::process::exit(exit_code);
}

// MIME type detection based on file extension
fn get_mime_type(path: &Path) -> &'static str {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return "application/octet-stream";
    };

    match ext {
        e if e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm") => {
            "text/html; charset=utf-8"
        }
        e if e.eq_ignore_ascii_case("css") => "text/css; charset=utf-8",
        e if e.eq_ignore_ascii_case("js") => "application/javascript; charset=utf-8",
        e if e.eq_ignore_ascii_case("json") => "application/json; charset=utf-8",
        e if e.eq_ignore_ascii_case("xml") => "application/xml; charset=utf-8",
        e if e.eq_ignore_ascii_case("txt") => "text/plain; charset=utf-8",
        e if e.eq_ignore_ascii_case("png") => "image/png",
        e if e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg") => "image/jpeg",
        e if e.eq_ignore_ascii_case("gif") => "image/gif",
        e if e.eq_ignore_ascii_case("mov") => "video/quicktime",
        e if e.eq_ignore_ascii_case("mp4") => "video/mp4",
        e if e.eq_ignore_ascii_case("svg") => "image/svg+xml",
        e if e.eq_ignore_ascii_case("ico") => "image/x-icon",
        e if e.eq_ignore_ascii_case("pdf") => "application/pdf",
        e if e.eq_ignore_ascii_case("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

// Serve static files with proper MIME types (sync FFI ABI)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_file(filename: *const c_char) -> *mut ResponseObject {
    if filename.is_null() {
        let (body_ptr, body_len) = leak_string_as_body("File not found".to_string());
        let response = Box::new(ResponseObject {
            status_code: 404,
            content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
            body: body_ptr,
            body_len,
            headers: arena_alloc_cstring(b""),
            missing_file_path: std::ptr::null_mut(),
        });
        return Box::into_raw(response);
    }

    let filename_cstr = unsafe { CStr::from_ptr(filename) };
    let append_index = filename_cstr.to_bytes().ends_with(b"/");

    let Some(path_cow) = cstr_to_path(filename) else {
        let (body_ptr, body_len) = leak_string_as_body("File not found".to_string());
        let response = Box::new(ResponseObject {
            status_code: 404,
            content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
            body: body_ptr,
            body_len,
            headers: arena_alloc_cstring(b""),
            missing_file_path: std::ptr::null_mut(),
        });
        return Box::into_raw(response);
    };

    let mut path_buf = path_cow.into_owned();
    if append_index {
        path_buf.push("index.html");
    }

    // Read file contents using the runtime helper, but expose a sync C ABI
    let read_result = block_on_in_runtime(async { tokio::fs::read(&path_buf).await });

    match read_result {
        Ok(content) => {
            let mime_type = get_mime_type(&path_buf);
            let (body_ptr, body_len) = leak_bytes_as_body(content);
            let response = Box::new(ResponseObject {
                status_code: 200,
                content_type: arena_alloc_cstring(mime_type.as_bytes()),
                body: body_ptr,
                body_len,
                headers: arena_alloc_cstring(b""),
                missing_file_path: std::ptr::null_mut(),
            });
            Box::into_raw(response)
        }
        Err(err) => {
            let missing_ptr = if err.kind() == std::io::ErrorKind::NotFound {
                let missing = path_buf.to_string_lossy();
                arena_cstring_from_bytes_checked(missing.as_bytes())
            } else {
                std::ptr::null_mut()
            };
            let (body_ptr, body_len) = leak_string_as_body("File not found".to_string());
            let response = Box::new(ResponseObject {
                status_code: 404,
                content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
                body: body_ptr,
                body_len,
                headers: arena_alloc_cstring(b""),
                missing_file_path: missing_ptr,
            });
            Box::into_raw(response)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_file_not_found(
    response: *mut ResponseObject,
    fallback: *const c_char,
) -> *mut ResponseObject {
    unsafe {
        if response.is_null() {
            // No original response; fall back to default handling
            let body = if fallback.is_null() {
                b"Not Found".to_vec()
            } else {
                CStr::from_ptr(fallback).to_bytes().to_owned()
            };
            let (body_ptr, body_len) = leak_bytes_as_body(body);
            let response = Box::new(ResponseObject {
                status_code: 404,
                content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
                body: body_ptr,
                body_len,
                headers: arena_alloc_cstring(b""),
                missing_file_path: std::ptr::null_mut(),
            });
            return Box::into_raw(response);
        }

        let mut original = Box::from_raw(response);
        if original.missing_file_path.is_null() {
            // Not a missing-file response; return it unchanged
            return Box::into_raw(original);
        }

        let fallback_path = if fallback.is_null() {
            None
        } else {
            cstr_to_path(fallback).map(|p| p.into_owned())
        }
        .filter(|p| !p.as_os_str().is_empty());

        let _ = ResponseObject::take_owned_string(&mut original.content_type);
        let _ = ResponseObject::take_owned_string(&mut original.headers);
        let _ = ResponseObject::take_owned_string(&mut original.missing_file_path);
        let _ = original.take_body_bytes();
        drop(original);

        if let Some(path) = fallback_path {
            if !path.as_os_str().is_empty() {
                if let Ok(content) = block_on_in_runtime(async { tokio::fs::read(&path).await }) {
                    let mime_type = get_mime_type(&path);
                    let (body_ptr, body_len) = leak_bytes_as_body(content);
                    let response = Box::new(ResponseObject {
                        status_code: 404,
                        content_type: arena_alloc_cstring(mime_type.as_bytes()),
                        body: body_ptr,
                        body_len,
                        headers: arena_alloc_cstring(b""),
                        missing_file_path: std::ptr::null_mut(),
                    });
                    return Box::into_raw(response);
                }
            }
        }

        let (body_ptr, body_len) = leak_string_as_body("Not Found".to_string());
        let response = Box::new(ResponseObject {
            status_code: 404,
            content_type: arena_alloc_cstring(b"text/plain; charset=utf-8"),
            body: body_ptr,
            body_len,
            headers: arena_alloc_cstring(b""),
            missing_file_path: std::ptr::null_mut(),
        });
        Box::into_raw(response)
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
pub unsafe extern "C" fn get_response_body(response: *const ResponseObject) -> *const u8 {
    if response.is_null() {
        return std::ptr::null();
    }
    unsafe { (*response).body as *const u8 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_response_body_len(response: *const ResponseObject) -> usize {
    if response.is_null() {
        return 0;
    }
    unsafe { (*response).body_len }
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

    // Mark the server as running immediately so the main thread parks
    // even if the async task hasn't been polled yet.
    SERVER_RUNNING.store(true, Ordering::Relaxed);

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

        let make_svc = make_service_fn(move |_conn| {
            let handler_addr = callback_addr;
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    handle_hyper_request(req, handler_addr)
                }))
            }
        });
        tokio::spawn(async move {
            std::thread::park();
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

fn dispatch_request_to_handler(
    handler_addr: usize,
    method: String,
    path: String,
    query: String,
    headers_raw: String,
    body_str: String,
) -> (i32, String, Vec<u8>, String) {
    // Scope arena allocations to this request so per-request C-strings don't accumulate
    let arena_ptr = get_or_create_global_arena();
    let mark = unsafe { arena_mark(arena_ptr) };

    let result = match std::panic::catch_unwind(move || unsafe {
        let body = if body_str.is_empty() {
            None
        } else {
            Some(body_str)
        };
        let request = RequestObject::from_owned_parts(
            Some(method),
            Some(path),
            Some(query),
            Some(headers_raw),
            body,
        );
        invoke_user_handler(handler_addr, request)
    }) {
        Ok(output) => output,
        Err(_) => (
            500,
            "text/plain; charset=utf-8".to_string(),
            b"Internal Server Error".to_vec(),
            String::new(),
        ),
    };

    unsafe {
        if !arena_ptr.is_null() {
            arena_release(arena_ptr, mark);
        }
    }

    result
}

unsafe fn invoke_user_handler(
    handler_addr: usize,
    request: RequestObject,
) -> (i32, String, Vec<u8>, String) {
    unsafe {
        let request_box = Box::new(request);
        let request_ptr = request_box.as_ref() as *const RequestObject;
        let func: extern "C" fn(*const RequestObject) -> *mut ResponseObject =
            std::mem::transmute::<usize, _>(handler_addr);
        let response_ptr = func(request_ptr);
        drop(request_box);
        materialize_response(response_ptr)
    }
}

unsafe fn materialize_response(
    response_ptr: *mut ResponseObject,
) -> (i32, String, Vec<u8>, String) {
    unsafe {
        if response_ptr.is_null() {
            return (
                404,
                "text/plain; charset=utf-8".to_string(),
                b"Not Found".to_vec(),
                String::new(),
            );
        }

        let status = get_response_status(response_ptr);
        let content_type = cstr_to_string(get_response_content_type(response_ptr));
        let headers = cstr_to_string(get_response_headers(response_ptr));
        let body_ptr = get_response_body(response_ptr);
        let body_len = get_response_body_len(response_ptr);
        let body = if body_ptr.is_null() || body_len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(body_ptr, body_len).to_vec()
        };
        let _ = Box::from_raw(response_ptr);
        (status, content_type, body, headers)
    }
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

    // Call the user callback directly and translate the response
    let (status_code, content_type, body, extra_headers) =
        dispatch_request_to_handler(handler_addr, method, path, query, headers_raw, body_str);

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
    Match,
    Else,
    False,
    For,
    Fun,
    If,
    OptionSome,
    OptionNone,
    ResultOk,
    ResultErr,
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
    OptionSome(Box<Expr>),
    OptionNone,
    ResultOk(Box<Expr>),
    ResultErr(Box<Expr>),
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
            Expr::OptionSome(value) => {
                let inner = infer_expr(value)?;
                Ok(Type::Option(Box::new(inner)))
            }
            Expr::OptionNone => Ok(Type::Option(Box::new(Type::Never))),
            Expr::ResultOk(value) => {
                let inner = infer_expr(value)?;
                Ok(Type::Result(Box::new(inner), Box::new(Type::Never)))
            }
            Expr::ResultErr(value) => {
                let inner = infer_expr(value)?;
                Ok(Type::Result(Box::new(Type::Never), Box::new(inner)))
            }
            Expr::Variable(v) => match ctx.var_types.get(v) {
                Some(t) => Ok(t.clone()),
                None => {
                    if let Some(l) = ctx.types.get(v) {
                        Ok(Type::Custom(l.clone()))
                    } else {
                        return type_error(
                            format!("Unknown identifier \"{v}\""),
                            Some(
                                "Declare it with `let` before using it, or ensure the spelling matches the definition.",
                            ),
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
                        Some(
                            "Only lists and strings support indexing. Make sure you're indexing a list or string.",
                        ),
                    );
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
                    );
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
                                Some(
                                    "Ensure both operands evaluate to booleans before using 'and' or 'or'.",
                                ),
                            );
                        }
                    }
                    BinOp::Plus => match (&lt, &rt) {
                        (Type::Num, Type::Num) => Ok(Type::Num),
                        (Type::Str, Type::Str) => Ok(Type::Str),
                        _ => type_error(
                            "The '+' operator needs two numbers or two strings".to_string(),
                            Some(
                                "Convert values to a shared type (both Num or both Str) before adding.",
                            ),
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
                                Some(
                                    "Check the available methods: insert(key, value) and get(key).",
                                ),
                            );
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
                        } else if prop == "join" {
                            if matches!(*t, Type::Str) {
                                Ok(Type::Function(
                                    vec![("joining".to_string(), Type::Str)],
                                    Box::new(Type::Str),
                                ))
                            } else {
                                type_error(
                                    format!(
                                        "You cannot call .join on a list unless it is a list of strings"
                                    ),
                                    None,
                                )
                            }
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
                            "exit" => Ok(Type::Function(
                                vec![("code".to_string(), Type::Num)],
                                Box::new(Type::Never),
                            )),
                            "json" => Ok(Type::Function(
                                vec![("payload".to_string(), Type::Str)],
                                Box::new(Type::Result(
                                    Box::new(Type::Kv(Box::new(Type::JsonValue))),
                                    Box::new(Type::Str),
                                )),
                            )),

                            "listen" => {
                                let mut request_fields = HashMap::new();
                                request_fields.insert("method".to_string(), Type::Str);
                                request_fields.insert("path".to_string(), Type::Str);
                                // Represent query and headers as strings (parsed, human-readable)
                                request_fields.insert("query".to_string(), Type::Str);
                                request_fields.insert("headers".to_string(), Type::Str);
                                request_fields
                                    .insert("body".to_string(), Type::Option(Box::new(Type::Str)));
                                Ok(Type::Function(
                                    vec![
                                        ("port".to_string(), Type::Num),
                                        (
                                            "handler".to_string(),
                                            Type::Function(
                                                vec![(
                                                    "req".to_string(),
                                                    Type::Custom(Custype::Object(request_fields)),
                                                )],
                                                Box::new(Type::WebReturn),
                                            ),
                                        ),
                                    ],
                                    Box::new(Type::Nil),
                                ))
                            }
                            "range" => Ok(Type::Function(vec![], Box::new(Type::RangeBuilder))),
                            "read" => Ok(Type::Function(
                                vec![("path".to_string(), Type::Str)],
                                Box::new(Type::Result(Box::new(Type::Str), Box::new(Type::Str))),
                            )),
                            "write" => Ok(Type::Function(
                                vec![
                                    ("path".to_string(), Type::Str),
                                    ("content".to_string(), Type::Str),
                                ],
                                Box::new(Type::Result(Box::new(Type::Str), Box::new(Type::Str))),
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
                                    Some(
                                        "Check the available builders like range(), read(), write(), web(), listen(), input(), and random().",
                                    ),
                                );
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
                    Type::JsonValue => match prop.as_str() {
                        "get" => Ok(Type::Function(
                            vec![("key".to_string(), Type::Str)],
                            Box::new(Type::Option(Box::new(Type::JsonValue))),
                        )),
                        "at" => Ok(Type::Function(
                            vec![("index".to_string(), Type::Num)],
                            Box::new(Type::Option(Box::new(Type::JsonValue))),
                        )),
                        "len" => Ok(Type::Function(vec![], Box::new(Type::Num))),
                        "is_null" => Ok(Type::Function(vec![], Box::new(Type::Bool))),
                        "stringify" => Ok(Type::Function(vec![], Box::new(Type::Str))),
                        "str" => Ok(Type::Function(
                            vec![],
                            Box::new(Type::Option(Box::new(Type::Str))),
                        )),
                        other => type_error(
                            format!("Property '{other}' not found on Json"),
                            Some(
                                "Available helpers: get(key), at(index), len(), is_null(), str(), stringify().",
                            ),
                        ),
                    },
                    Type::Num => match prop.as_str() {
                        "str" => Ok(Type::Function(vec![], Box::new(Type::Str))),
                        other => type_error(
                            format!("Unknown Num helper '{other}'"),
                            Some(
                                "Did you mean to call num.str()? That's the only helper currently exposed.",
                            ),
                        ),
                    },
                    Type::Custom(Custype::Object(fields)) => {
                        let is_type_reference = if let Expr::Variable(name) = &**obj {
                            !ctx.var_types.contains_key(name) && ctx.types.contains_key(name)
                        } else {
                            false
                        };

                        if is_type_reference && prop == "from_json" {
                            return Ok(Type::Function(
                                vec![("payload".to_string(), Type::Str)],
                                Box::new(Type::Option(Box::new(Type::Custom(Custype::Object(
                                    fields.clone(),
                                ))))),
                            ));
                        }

                        if !is_type_reference && prop == "json" && !fields.contains_key(prop) {
                            return Ok(Type::Function(vec![], Box::new(Type::Str)));
                        }

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
                        let is_type_reference = if let Expr::Variable(name) = &**obj {
                            !ctx.var_types.contains_key(name) && ctx.types.contains_key(name)
                        } else {
                            false
                        };

                        if is_type_reference && prop == "from_json" {
                            return Ok(Type::Function(
                                vec![("payload".to_string(), Type::Str)],
                                Box::new(Type::Option(Box::new(Type::Custom(Custype::Enum(
                                    variants.clone(),
                                ))))),
                            ));
                        }

                        if is_type_reference {
                            return type_error(
                                format!("'{prop}' is not available on enum type references"),
                                Some(
                                    "Use TypeName.from_json(payload) to construct an enum from JSON.",
                                ),
                            );
                        }

                        if prop == "json" {
                            return Ok(Type::Function(vec![], Box::new(Type::Str)));
                        }

                        if let Some(variant) = variants.iter().find(|variant| variant.name == *prop)
                        {
                            if variant.payload.is_empty() {
                                Ok(obj_type.clone())
                            } else {
                                let params = variant
                                    .payload
                                    .iter()
                                    .enumerate()
                                    .map(|(idx, ty)| (format!("payload{idx}"), ty.clone()))
                                    .collect();
                                Ok(Type::Function(params, Box::new(obj_type.clone())))
                            }
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
                                Some(
                                    "Available helpers: len, num, starts_with, ends_with, contains, replace, split.",
                                ),
                            )
                        }
                    }
                    Type::Option(inner) => match prop.as_str() {
                        "or_else" => Ok(Type::Function(
                            vec![("fallback".to_string(), *inner.clone())],
                            inner.clone(),
                        )),
                        "default" => Ok(Type::Function(
                            vec![("def".to_string(), *inner.clone())],
                            Box::new(*inner.clone()),
                        )),
                        "is_some" => Ok(Type::Function(vec![], Box::new(Type::Bool))),
                        "is_none" => Ok(Type::Function(vec![], Box::new(Type::Bool))),
                        "unwrap" => Ok(Type::Function(vec![], Box::new(*inner.clone()))),
                        "expect" => Ok(Type::Function(
                            vec![("message".to_string(), Type::Str)],
                            Box::new(*inner.clone()),
                        )),
                        _ => type_error(
                            format!("Property '{prop}' not found on Option"),
                            Some(
                                "Options expose default(value), or_else(value), is_some(), is_none(), unwrap(), and expect(message).",
                            ),
                        ),
                    },
                    Type::Result(ok_ty, err_ty) => match prop.as_str() {
                        "is_ok" => Ok(Type::Function(vec![], Box::new(Type::Bool))),
                        "is_err" => Ok(Type::Function(vec![], Box::new(Type::Bool))),
                        "unwrap" => Ok(Type::Function(vec![], Box::new(*ok_ty.clone()))),
                        "unwrap_err" => Ok(Type::Function(vec![], Box::new(*err_ty.clone()))),
                        "expect" => Ok(Type::Function(
                            vec![("message".to_string(), Type::Str)],
                            Box::new(*ok_ty.clone()),
                        )),
                        "expect_err" => Ok(Type::Function(
                            vec![("message".to_string(), Type::Str)],
                            Box::new(*err_ty.clone()),
                        )),
                        _ => type_error(
                            format!("Property '{prop}' not found on Result"),
                            Some(
                                "Results expose is_ok(), is_err(), unwrap(), unwrap_err(), expect(message), and expect_err(message).",
                            ),
                        ),
                    },
                    Type::WebReturn => match prop.as_str() {
                        "not_found" => Ok(Type::Function(
                            vec![("fallback".to_string(), Type::Str)],
                            Box::new(Type::WebReturn),
                        )),
                        other => type_error(
                            format!("Property '{other}' not found on WebReturn"),
                            Some("Web responses currently expose not_found(fallback_path)."),
                        ),
                    },
                    other => type_error(
                        format!("Cannot access property '{prop}' on type {other:?}"),
                        Some(
                            "Check the value before using '.' or convert it to an object with that field.",
                        ),
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

                if let Expr::Get(obj, method_name) = &**callee {
                    match method_name.as_str() {
                        "unwrap" => {
                            let target_ty = infer_expr(obj)?;
                            match target_ty {
                                Type::Option(_) => ctx.emit_warning(
                                    line_hint,
                                    "Option.unwrap() WILL crash if this value is None.",
                                    Some(
                                        "Prefer pattern matching, .default(...), or expect(\"message\") to handle the None branch explicitly."
                                            .to_string(),
                                    ),
                                ),
                                Type::Result(_, _) => ctx.emit_warning(
                                    line_hint,
                                    "Result.unwrap() WILL crash if this value is Err.",
                                    Some(
                                        "Handle the Err case or use expect(\"message\") so failures carry context instead of aborting."
                                            .to_string(),
                                    ),
                                ),
                                _ => {}
                            }
                        }
                        "unwrap_err" => {
                            if matches!(infer_expr(obj)?, Type::Result(_, _)) {
                                ctx.emit_warning(
                                    line_hint,
                                    "Result.unwrap_err() WILL crash if this value is Ok.",
                                    Some(
                                        "Consider match/if-let or expect_err(\"message\") to document why the Ok branch is impossible."
                                            .to_string(),
                                    ),
                                );
                            }
                        }
                        _ => {}
                    }
                }

                if let Type::Function(params, ret_type) = &callee_type {
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
                                            Some(
                                                "Convert the key to a string before calling insert.",
                                            ),
                                        );
                                    }
                                    // Skip strict check for value here; caller will solidify type.
                                    return Ok((**ret_type).clone());
                                }
                            }
                        }
                    }
                    // verify each arg’s inferred type against the declared parameter type
                    for (i, (_, param_ty)) in params.iter().enumerate() {
                        let arg_ty = infer_expr(&args[i])?;
                        match (param_ty, &arg_ty) {
                            (
                                Type::Function(expected_params, expected_ret),
                                Type::Function(actual_params, actual_ret),
                            ) => {
                                if expected_params != actual_params {
                                    return type_error(
                                        format!(
                                            "Argument {} expects parameters {:?}, but the provided function takes {:?}",
                                            i + 1,
                                            expected_params,
                                            actual_params,
                                        ),
                                        Some(
                                            "Update the callback signature to match the expected parameters.",
                                        ),
                                    );
                                }
                                if **expected_ret != **actual_ret && **actual_ret != Type::Never {
                                    return type_error(
                                        format!(
                                            "Argument {} should return {:?}, but returns {:?}",
                                            i + 1,
                                            **expected_ret,
                                            **actual_ret,
                                        ),
                                        Some("Adjust the function to return the expected type."),
                                    );
                                }
                            }
                            (Type::Function(_, _), _) => {
                                return type_error(
                                    format!(
                                        "Argument {} should be a function, but it has type {:?}",
                                        i + 1,
                                        arg_ty,
                                    ),
                                    Some(
                                        "Pass a lambda or named function that matches the expected callback signature.",
                                    ),
                                );
                            }
                            (_, Type::Never) => {
                                // Expressions of type Never can flow into any parameter.
                            }
                            (expected, actual) => {
                                if expected != actual {
                                    return type_error(
                                        format!(
                                            "Argument {} has type {:?}, but {:?} is required",
                                            i + 1,
                                            actual,
                                            expected,
                                        ),
                                        Some(
                                            "Cast the argument or adjust the function signature so the types agree.",
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    Ok((**ret_type).clone())
                } else {
                    type_error(
                        format!(
                            "Can only call functions, found value of type {:?}",
                            callee_type
                        ),
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
    EnumDestructure {
        enum_name: String,
        enum_type: Type,
        variant: String,
        patterns: Vec<EnumPattern>,
        body: Instruction,
    },
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
    Expr(Expr, Type),
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
    generic_types: HashMap<String, GenericTypeTemplate>,
    deserialize_plans: HashMap<String, DeserializeDescriptor>,
}

impl Default for ModuleInfo {
    fn default() -> Self {
        Self {
            functions: HashMap::new(),
            constants: HashMap::new(),
            field_types: HashMap::new(),
            types: HashMap::new(),
            generic_types: HashMap::new(),
            deserialize_plans: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct GenericTypeTemplate {
    params: Vec<String>,
    body: Custype,
}

#[derive(Clone, Debug)]
struct DeserializeField {
    name: String,
    ty: Type,
}

#[derive(Clone, Debug)]
struct DeserializeDescriptor {
    canonical_name: String,
    fields: Vec<DeserializeField>,
}

#[derive(Debug, Clone)]
struct Warning {
    line: Option<usize>,
    message: String,
    note: Option<String>,
}

#[derive(Default, Clone)]
struct PreCtx {
    var_types: HashMap<String, Type>,
    types: HashMap<String, Custype>,
    generic_types: HashMap<String, GenericTypeTemplate>,
    deserialize_registry: HashMap<String, DeserializeDescriptor>,
    // Loaded modules and their exports (types only; no execution)
    modules: HashMap<String, ModuleInfo>,
    current_line: Cell<Option<usize>>,
    warnings: RefCell<Vec<Warning>>,
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

    fn emit_warning<M: Into<String>>(&self, line: Option<usize>, message: M, note: Option<String>) {
        self.warnings.borrow_mut().push(Warning {
            line,
            message: message.into(),
            note,
        });
    }

    fn take_warnings(&self) -> Vec<Warning> {
        self.warnings.borrow_mut().drain(..).collect()
    }

    fn substitute_type(&self, ty: &Type, bindings: &HashMap<String, Type>) -> Type {
        match ty {
            Type::GenericParam(name) => bindings
                .get(name)
                .cloned()
                .unwrap_or(Type::GenericParam(name.clone())),
            Type::List(inner) => Type::List(Box::new(self.substitute_type(inner, bindings))),
            Type::Option(inner) => Type::Option(Box::new(self.substitute_type(inner, bindings))),
            Type::Kv(inner) => Type::Kv(Box::new(self.substitute_type(inner, bindings))),
            Type::Function(params, ret) => {
                let substituted_params = params
                    .iter()
                    .map(|(name, param_ty)| {
                        (name.clone(), self.substitute_type(param_ty, bindings))
                    })
                    .collect();
                let substituted_ret = Box::new(self.substitute_type(ret, bindings));
                Type::Function(substituted_params, substituted_ret)
            }
            Type::Custom(custype) => {
                let substituted = self.substitute_custype(custype, bindings);
                Type::Custom(substituted)
            }
            other => other.clone(),
        }
    }

    fn substitute_custype(&self, custype: &Custype, bindings: &HashMap<String, Type>) -> Custype {
        match custype {
            Custype::Object(fields) => {
                let mut resolved = HashMap::new();
                for (fname, fty) in fields {
                    resolved.insert(fname.clone(), self.substitute_type(fty, bindings));
                }
                Custype::Object(resolved)
            }
            Custype::Enum(variants) => Custype::Enum(variants.clone()),
        }
    }

    fn instantiate_generic_type(&mut self, name: &str, args: &[Type]) -> Result<Custype, String> {
        let template = self.generic_types.get(name).ok_or_else(|| {
            format!("Type '{name}' is not declared or does not support type parameters")
        })?;

        if template.params.len() != args.len() {
            return Err(format!(
                "Type '{name}' expects {} type parameter(s), found {}",
                template.params.len(),
                args.len()
            ));
        }

        let mut bindings = HashMap::new();
        for (param, arg_ty) in template.params.iter().zip(args.iter()) {
            bindings.insert(param.clone(), arg_ty.clone());
        }

        let instantiated = self.substitute_custype(&template.body, &bindings);
        if let Custype::Object(ref fmap) = instantiated {
            self.register_object_descriptor(name, args, fmap);
        }
        Ok(instantiated)
    }

    fn canonicalize_type(&self, ty: &Type) -> String {
        match ty {
            Type::GenericParam(name) => format!("{name}"),
            Type::Num => "Num".to_string(),
            Type::Str => "Str".to_string(),
            Type::Bool => "Bool".to_string(),
            Type::Nil => "Nil".to_string(),
            Type::Never => "!".to_string(),
            Type::Io => "Io".to_string(),
            Type::WebReturn => "WebReturn".to_string(),
            Type::RangeBuilder => "Range".to_string(),
            Type::JsonValue => "JsonValue".to_string(),
            Type::Kv(inner) => format!("Obj({})", self.canonicalize_type(inner)),
            Type::List(inner) => format!("List({})", self.canonicalize_type(inner)),
            Type::Option(inner) => format!("Option({})", self.canonicalize_type(inner)),
            Type::Result(ok, err) => format!(
                "Result({}, {})",
                self.canonicalize_type(ok),
                self.canonicalize_type(err)
            ),
            Type::Function(params, ret) => {
                let args = params
                    .iter()
                    .map(|(name, ty)| format!("{name}:{}", self.canonicalize_type(ty)))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("Fn<{args}> -> {}", self.canonicalize_type(ret))
            }
            Type::Custom(Custype::Object(fields)) => {
                let mut entries: Vec<_> = fields.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let inner = entries
                    .into_iter()
                    .map(|(fname, fty)| format!("{fname}:{}", self.canonicalize_type(fty)))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("Object{{{inner}}}")
            }
            Type::Custom(Custype::Enum(variants)) => {
                let rendered = variants
                    .iter()
                    .map(|variant| {
                        if variant.payload.is_empty() {
                            variant.name.clone()
                        } else {
                            let payload = variant
                                .payload
                                .iter()
                                .map(|ty| self.canonicalize_type(ty))
                                .collect::<Vec<_>>()
                                .join(",");
                            format!("{}({payload})", variant.name)
                        }
                    })
                    .collect::<Vec<_>>();
                format!("Enum{{{}}}", rendered.join("|"))
            }
        }
    }

    fn register_object_descriptor(
        &mut self,
        name: &str,
        args: &[Type],
        fields: &HashMap<String, Type>,
    ) {
        let key = if args.is_empty() {
            name.to_string()
        } else {
            let rendered_args = args
                .iter()
                .map(|arg| self.canonicalize_type(arg))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{name}<{}>", rendered_args)
        };

        if self.deserialize_registry.contains_key(&key) {
            return;
        }

        let mut ordered_fields: Vec<_> = fields.iter().collect();
        ordered_fields.sort_by(|a, b| a.0.cmp(b.0));
        let descriptor = DeserializeDescriptor {
            canonical_name: key.clone(),
            fields: ordered_fields
                .into_iter()
                .map(|(fname, fty)| DeserializeField {
                    name: fname.clone(),
                    ty: fty.clone(),
                })
                .collect(),
        };

        self.deserialize_registry
            .entry(key.clone())
            .or_insert_with(|| descriptor.clone());

        let structural_key = self.canonicalize_type(&Type::Custom(Custype::Object(fields.clone())));
        self.deserialize_registry
            .entry(structural_key)
            .or_insert_with(|| descriptor);
    }

    fn ensure_deserializable(&mut self, ty: &Type) -> Result<(), String> {
        match ty {
            Type::Num | Type::Str | Type::Bool => Ok(()),
            Type::Option(inner) => self.ensure_deserializable(inner),
            Type::List(inner) => self.ensure_deserializable(inner),
            Type::Kv(inner) => self.ensure_deserializable(inner),
            Type::Custom(Custype::Object(fields)) => {
                let signature =
                    self.canonicalize_type(&Type::Custom(Custype::Object(fields.clone())));
                if self.deserialize_registry.contains_key(&signature) {
                    Ok(())
                } else {
                    Err(format!(
                        "Type with fields {:?} is not registered for deserialization",
                        fields.keys().collect::<Vec<_>>()
                    ))
                }
            }
            Type::Custom(Custype::Enum(variants)) => {
                let signature =
                    self.canonicalize_type(&Type::Custom(Custype::Enum(variants.clone())));
                if enum_signature_registry()
                    .lock()
                    .ok()
                    .map(|m| m.contains_key(&signature))
                    .unwrap_or(false)
                {
                    Ok(())
                } else {
                    Ok(()) // Enum descriptors are registered during codegen; allow here.
                }
            }
            Type::GenericParam(name) => Err(format!(
                "Cannot deserialize unresolved generic parameter '{name}'"
            )),
            other => Err(format!(
                "Type {other:?} is not supported for JSON deserialization"
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct EnumVariant {
    name: String,
    payload: Vec<Type>,
}

#[derive(Debug, Clone)]
enum EnumPattern {
    Binding(String),
    Literal(Expr),
}

#[derive(Clone, Debug, PartialEq)]
enum Custype {
    Object(HashMap<String, Type>),
    Enum(Vec<EnumVariant>),
}

impl Default for Custype {
    fn default() -> Self {
        Custype::Enum(vec![])
    }
}

#[derive(Debug, Clone)]
enum Type {
    GenericParam(String),
    Num,
    Str,
    Bool,
    Nil,
    Never,
    Io,
    WebReturn,
    RangeBuilder,
    JsonValue,
    Kv(Box<Type>),
    List(Box<Type>),
    Option(Box<Type>),
    Result(Box<Type>, Box<Type>),
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
            (_, Type::GenericParam(_)) => Some(self.clone()),
            (Type::GenericParam(_), other) => Some(other.clone()),
            (Type::Never, other) => Some(other.clone()),
            (other, Type::Never) => Some(other.clone()),
            (Type::List(b), Type::List(e)) if **b == Type::Nil => Some(Type::List(e.clone())),
            (Type::Kv(b), Type::List(e)) if **b == Type::Nil => Some(Type::Kv(e.clone())),
            (Type::Option(inner_actual), Type::Option(inner_expected)) => {
                if **inner_actual == Type::Never {
                    Some(Type::Option(inner_expected.clone()))
                } else if **inner_expected == Type::Never {
                    Some(Type::Option(inner_actual.clone()))
                } else if inner_actual == inner_expected {
                    Some(Type::Option(inner_expected.clone()))
                } else {
                    None
                }
            }
            (Type::Result(ok_actual, err_actual), Type::Result(ok_expected, err_expected)) => {
                let ok = if **ok_actual == Type::Never {
                    ok_expected.clone()
                } else if **ok_expected == Type::Never {
                    ok_actual.clone()
                } else if ok_actual == ok_expected {
                    ok_expected.clone()
                } else {
                    return None;
                };
                let err = if **err_actual == Type::Never {
                    err_expected.clone()
                } else if **err_expected == Type::Never {
                    err_actual.clone()
                } else if err_actual == err_expected {
                    err_expected.clone()
                } else {
                    return None;
                };
                Some(Type::Result(ok, err))
            }
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
    if matches!(old, Type::Never) {
        return Some(new.clone());
    }
    if matches!(new, Type::Never) {
        return Some(old.clone());
    }

    match (old, new) {
        (Type::Nil, other) => Some(Type::Option(Box::new(other.clone()))),
        (other, Type::Nil) => Some(Type::Option(Box::new(other.clone()))),
        (Type::GenericParam(_), other) => Some(other.clone()),
        (other, Type::GenericParam(_)) => Some(other.clone()),
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
            (Type::GenericParam(left), Type::GenericParam(right)) => left == right,
            (Type::Num, Type::Num)
            | (Type::Str, Type::Str)
            | (Type::Bool, Type::Bool)
            | (Type::Nil, Type::Nil)
            | (Type::Never, Type::Never)
            | (Type::Io, Type::Io)
            | (Type::WebReturn, Type::WebReturn)
            | (Type::RangeBuilder, Type::RangeBuilder)
            | (Type::JsonValue, Type::JsonValue) => true,

            (Type::List(left), Type::List(right)) | (Type::Option(left), Type::Option(right)) => {
                left == right
            }
            (Type::Result(ok_l, err_l), Type::Result(ok_r, err_r)) => {
                ok_l == ok_r && err_l == err_r
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
            Self::Match => "match".to_string(),
            Self::Else => "else".to_string(),
            Self::False => "false".to_string(),
            Self::For => "for".to_string(),
            Self::Fun => "fun".to_string(),
            Self::If => "if".to_string(),
            Self::OptionSome => "Some".to_string(),
            Self::OptionNone => "None".to_string(),
            Self::ResultOk => "Ok".to_string(),
            Self::ResultErr => "Err".to_string(),
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
        "else" => Else,
        "false" => False,
        "for" => For,
        "in" => In,
        "fun" => Fun,
        "if" => If,
        "match" => Match,
        "Some" => OptionSome,
        "None" => OptionNone,
        "Ok" => ResultOk,
        "Err" => ResultErr,
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
            Instruction::Expr(_, ty) => {
                if ty == Type::Never {
                    return true;
                } else {
                    continue;
                }
            }
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
            Instruction::Match { expr: _, arms } => {
                let mut all_certified = true;
                for arm in arms {
                    let body = match arm {
                        MatchArm::CatchAll(_, b) => b,
                        MatchArm::Literal(_, a) => a,
                        MatchArm::EnumDestructure { body, .. } => body,
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

            Instruction::Return(_) => true,

            _ => false,
        },
    }
}

#[cfg(not(feature = "runtime-lib"))]
#[derive(Clap, Debug)]
#[command(about, long_about = None, subcommand_required = false, arg_required_else_help = false)]
struct Args {
    /// Shows debugging info
    #[arg(short, long, default_value_t = false)]
    debug: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[cfg(not(feature = "runtime-lib"))]
#[derive(Clap, Debug)]
enum Commands {
    Run {
        filename: Option<String>,
    },
    Build {
        filename: Option<String>,
    },
    Format {
        filename: Option<String>,
    },
    #[command(external_subcommand)]
    Fallback(Vec<String>),
}

#[cfg(not(feature = "runtime-lib"))]
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
            let context = inkwell::context::Context::create();
            let module = context.create_module("sum");
            let arena_global = module.add_global(
                context.ptr_type(AddressSpace::default()),
                None,
                "__qs_arena",
            );
            arena_global.set_initializer(&context.ptr_type(AddressSpace::default()).const_null());
            let execution_engine = module
                .create_jit_execution_engine(inkwell::OptimizationLevel::Aggressive)
                .unwrap();
            let initial_quick_types = parser.pctx.var_types.clone();
            let parser_ctx = parser.pctx;
            let warnings = parser_ctx.take_warnings();
            for warning in warnings {
                let reset = "\x1b[0m";
                let line_color = "\x1b[1;37m";
                let label_color = "\x1b[1;33m";
                let message_color = "\x1b[33m";
                let tip_label_color = "\x1b[1;33m";
                let tip_color = "\x1b[36m";

                let mut text = String::new();
                if let Some(line) = warning.line {
                    text.push_str(&format!("{line_color}[Line {line}]:{reset} "));
                }
                text.push_str(&format!(
                    "{label_color}Warning:{reset} {message_color}{}{reset}",
                    warning.message
                ));
                if let Some(note) = warning.note {
                    if !note.is_empty() {
                        text.push_str(&format!(
                            "\n  {tip_label_color}Tip:{reset} {tip_color}{note}{reset}"
                        ));
                    }
                }
                eprintln!("{text}");
            }
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
                current_arena: arena_global,
            };

            // seed the C PRNG so io.random() varies each run
            unsafe {
                // get current epoch seconds
                let now = time(ptr::null_mut());
                srand(now as u32);
            }
            let sum = codegen
                .run_code(CodegenMode::Jit)
                .ok_or("Unable to JIT compile code")
                .unwrap();
            if debug {
                let _ = codegen.module.print_to_file("./ll.v");
            }

            unsafe {
                let res = sum.call();
                if !SERVER_RUNNING.load(Ordering::Relaxed) && !GLOBAL_ARENA_PTR.is_null() {
                    arena_destroy(GLOBAL_ARENA_PTR);
                }
                if res != 0.0 {
                    std::process::exit(res as i32);
                }
            }

            // If an HTTP server was started, keep the process alive by parking the main thread.
            if SERVER_RUNNING.load(Ordering::Relaxed) {
                std::thread::park();
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(65);
        }
    }
}

#[cfg(not(feature = "runtime-lib"))]
fn execute_build(filename: String, debug: bool) {
    let Ok(contents) = std::fs::read_to_string(&filename) else {
        eprintln!("Os error while reading file {filename}. Please try again later");
        std::process::exit(70);
    };

    let tokens = tokenize(contents.chars().collect());

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
            let context = inkwell::context::Context::create();
            let module = context.create_module("sum");
            let arena_global = module.add_global(
                context.ptr_type(AddressSpace::default()),
                None,
                "__qs_arena",
            );
            arena_global.set_initializer(&context.ptr_type(AddressSpace::default()).const_null());
            let execution_engine = module
                .create_jit_execution_engine(inkwell::OptimizationLevel::Aggressive)
                .unwrap();
            let initial_quick_types = parser.pctx.var_types.clone();
            let parser_ctx = parser.pctx;
            let warnings = parser_ctx.take_warnings();
            for warning in warnings {
                let reset = "\x1b[0m";
                let line_color = "\x1b[1;37m";
                let label_color = "\x1b[1;33m";
                let message_color = "\x1b[33m";
                let tip_label_color = "\x1b[1;33m";
                let tip_color = "\x1b[36m";

                let mut text = String::new();
                if let Some(line) = warning.line {
                    text.push_str(&format!("{line_color}[Line {line}]:{reset} "));
                }
                text.push_str(&format!(
                    "{label_color}Warning:{reset} {message_color}{}{reset}",
                    warning.message
                ));
                if let Some(note) = warning.note {
                    if !note.is_empty() {
                        text.push_str(&format!(
                            "\n  {tip_label_color}Tip:{reset} {tip_color}{note}{reset}"
                        ));
                    }
                }
                eprintln!("{text}");
            }

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
                current_arena: arena_global,
            };

            unsafe {
                let now = time(ptr::null_mut());
                srand(now as u32);
            }

            if codegen.run_code(CodegenMode::EmitObject).is_none() {
                eprintln!("Failed to lower program");
                std::process::exit(65);
            }

            let build_dir = Path::new("build");
            if let Err(err) = std::fs::create_dir_all(build_dir) {
                eprintln!("Failed to create build directory: {err}");
                std::process::exit(70);
            }

            if debug {
                let _ = codegen.module.print_to_file(build_dir.join("ll.v"));
            }

            let triple = inkwell::targets::TargetMachine::get_default_triple();
            let target = inkwell::targets::Target::from_triple(&triple).unwrap();
            let cpu = inkwell::targets::TargetMachine::get_host_cpu_name();
            let features = inkwell::targets::TargetMachine::get_host_cpu_features();
            let machine = target
                .create_target_machine(
                    &triple,
                    &cpu.to_string(),
                    &features.to_string(),
                    inkwell::OptimizationLevel::Aggressive,
                    inkwell::targets::RelocMode::Default,
                    inkwell::targets::CodeModel::Default,
                )
                .expect("Could not create target machine");

            let obj_path = build_dir.join("program.o");
            if let Err(err) = machine.write_to_file(
                &codegen.module,
                inkwell::targets::FileType::Object,
                &obj_path,
            ) {
                eprintln!("Failed to emit object file: {err}");
                std::process::exit(65);
            }

            let output_bin = build_dir.join("program");

            let runtime_lib_path = build_dir.join("libquick.a");
            // Prefer an explicit override, then a freshly built runtime from disk, and finally the embedded bytes.
            if let Ok(path_override) = std::env::var("QUICK_RUNTIME_LIB") {
                let override_path = PathBuf::from(&path_override);
                if let Err(err) = std::fs::copy(&override_path, &runtime_lib_path) {
                    eprintln!(
                        "Failed to copy runtime lib from {}: {err}; falling back to defaults",
                        override_path.display()
                    );
                }
            }

            if !runtime_lib_path.exists() {
                let disk_runtime = PathBuf::from("target/runtime/release/libquick_runtime.a");
                if disk_runtime.exists() {
                    if let Err(err) = std::fs::copy(&disk_runtime, &runtime_lib_path) {
                        eprintln!(
                            "Failed to copy runtime lib from {}: {err}; falling back to embedded runtime",
                            disk_runtime.display()
                        );
                    }
                }
            }

            if !runtime_lib_path.exists() {
                if let Err(e) = std::fs::write(&runtime_lib_path, &LIBQUICK) {
                    eprintln!("Error writing embedded runtime library: {e}");
                }
            }
            let (linker_override, ld_override) = bundled_linker();

            let mut link_args = Vec::new();
            // On macOS, prefer the platform ld64 to avoid lld complaining about Mach-O archives.
            if cfg!(not(target_os = "macos")) {
                if let Some(ld) = ld_override {
                    link_args.push(format!("-fuse-ld={}", ld.display()));
                }
            }

            #[cfg(target_os = "macos")]
            if let Some(sdk) = macos_sdk_root() {
                link_args.push(format!("-isysroot={}", sdk.display()));
                link_args.push(format!("-Wl,-syslibroot,{}", sdk.display()));
            }
            link_args.extend([
                obj_path.to_string_lossy().to_string(),
                runtime_lib_path.to_string_lossy().to_string(),
                "-o".to_string(),
                output_bin.to_string_lossy().to_string(),
            ]);

            if cfg!(target_os = "macos") {
                // macOS libSystem provides pthread/libm/libdl; no extra libs needed.
            } else {
                link_args.extend([
                    "-lm".to_string(),
                    "-ldl".to_string(),
                    "-lpthread".to_string(),
                ]);
            }

            #[cfg(target_os = "macos")]
            {
                link_args.push("-framework".to_string());
                link_args.push("CoreServices".to_string());

                if let Some(target) = detect_macos_deployment_target() {
                    link_args.push(format!("-mmacosx-version-min={target}"));
                }
            }

            #[cfg(target_os = "macos")]
            {
                link_args.push("-Wl,-e,_qs_run_main".to_string());
            }

            #[cfg(not(target_os = "macos"))]
            {
                link_args.push("-Wl,-e,qs_run_main".to_string());
            }

            let linker = linker_override.unwrap_or_else(|| std::ffi::OsString::from("cc"));
            let link_status = std::process::Command::new(&linker)
                .args(&link_args)
                .status();

            match link_status {
                Ok(status) if status.success() => {
                    eprintln!("Built {}/program", build_dir.display());
                    let _ = std::fs::remove_file(&obj_path);
                    let _ = std::fs::remove_file(&runtime_lib_path);
                }
                Ok(status) => {
                    eprintln!("Linker failed with status {status}");
                    std::process::exit(65);
                }
                Err(err) => {
                    eprintln!("Failed to invoke linker: {err}");
                    std::process::exit(65);
                }
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(65);
        }
    }
}

fn bundled_linker() -> (Option<std::ffi::OsString>, Option<std::path::PathBuf>) {
    if let Some(env_linker) = std::env::var_os("QUICK_LINKER") {
        return (Some(env_linker), None);
    }

    if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
        let bin = home.join(".quick").join("bin");
        let clang = bin.join("clang");
        let ld_lld = bin.join("ld.lld");
        if clang.exists() {
            let ld = if ld_lld.exists() { Some(ld_lld) } else { None };
            return (Some(clang.into_os_string()), ld);
        }
    }

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    if let Some(dir) = exe_dir {
        let llvm_bin = dir.join("llvm").join("bin");
        let clang = llvm_bin.join("clang");
        let ld_lld = llvm_bin.join("ld.lld");
        if clang.exists() {
            let ld = if ld_lld.exists() { Some(ld_lld) } else { None };
            return (Some(clang.into_os_string()), ld);
        }
    }

    (None, None)
}

#[cfg(target_os = "macos")]
fn macos_sdk_root() -> Option<std::path::PathBuf> {
    let validate = |p: &std::path::Path| p.join("usr/lib/libSystem.tbd").exists();

    if let Ok(sdk) = std::env::var("QUICK_SYSROOT").or_else(|_| std::env::var("SDKROOT")) {
        let pb = std::path::PathBuf::from(&sdk);
        if validate(&pb) {
            return Some(pb);
        }
    }

    if let Ok(output) = std::process::Command::new("xcrun")
        .args(["--sdk", "macosx", "--show-sdk-path"])
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let pb = std::path::PathBuf::from(path);
            if validate(&pb) {
                return Some(pb);
            }
        }
    }

    // Fallback: scan CommandLineTools SDK directory for a MacOSX*.sdk
    let clt_sdks = std::path::Path::new("/Library/Developer/CommandLineTools/SDKs");
    if let Ok(entries) = std::fs::read_dir(clt_sdks) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("MacOSX") && n.ends_with(".sdk"))
                .unwrap_or(false)
                && validate(&path)
            {
                return Some(path);
            }
        }
    }

    None
}

#[cfg(not(feature = "runtime-lib"))]
#[tokio::main]
async fn main() {
    let args = Args::parse();
    let debug = args.debug;

    ARENA_DEBUG_CHECKS.store(debug, Ordering::Relaxed);

    let command = args.command.unwrap_or(Commands::Run { filename: None });

    match command {
        Commands::Run { filename } => {
            let filename = filename.unwrap_or("./src/main.qx".to_string());
            execute_run(filename, debug);
        }
        Commands::Build { filename } => {
            let filename = filename.unwrap_or("./src/main.qx".to_string());
            execute_build(filename, debug);
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

            let push_indent = |buf: &mut String, indent: usize, line_open: &mut bool| {
                if !*line_open {
                    for _ in 0..indent {
                        buf.push('\t');
                    }
                    *line_open = true;
                }
            };

            let trim_trailing_space = |buf: &mut String| {
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
                                    | Return
                                    | Else
                                    | OptionNone
                                    | ResultOk
                                    | ResultErr
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
                            Some(If | For | While | Fun | Print | Reprint | Return | Let | Use)
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
                    And | Or | Object | Enum | Else | False | For | Fun | If | Match | Print
                    | Reprint | Return | Break | Super | This | True | Let | While | Use | In
                    | OptionSome | OptionNone | ResultOk | ResultErr => {
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
                            Else => "else",
                            False => "false",
                            For => "for",
                            Fun => "fun",
                            If => "if",
                            Match => "match",
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
                            OptionSome => "Some",
                            OptionNone => "None",
                            ResultOk => "Ok",
                            ResultErr => "Err",
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

#[cfg(feature = "runtime-lib")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_run_main() -> i32 {
    unsafe extern "C" {
        fn main() -> f64;
    }

    let res = unsafe { main() };
    if SERVER_RUNNING.load(Ordering::Relaxed) {
        std::thread::park();
    }
    res.round() as i32
}

// Keep runtime C-ABI exports alive in the static library. This function is
// never called, but taking the addresses of the exported symbols forces codegen
// to retain them even when they are otherwise unreferenced within the crate.
#[cfg(feature = "runtime-lib")]
#[unsafe(no_mangle)]
pub extern "C" fn __qs_export_roots() -> usize {
    let addrs: [usize; 10] = [
        qs_register_struct_descriptor as usize,
        arena_create as usize,
        arena_alloc as usize,
        arena_mark as usize,
        arena_release as usize,
        arena_pin as usize,
        arena_retain as usize,
        arena_release_ref as usize,
        arena_destroy as usize,
        qs_run_main as usize,
    ];
    addrs.iter().fold(0usize, |acc, p| acc.wrapping_add(*p))
}

type SumFunc = unsafe extern "C" fn() -> f64;

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

fn find_runtime_archive(target_dir: &Path) -> Option<PathBuf> {
    let release_dir = target_dir.join("release");
    let direct = release_dir.join("libquick.a");
    if direct.exists() {
        return Some(direct);
    }

    fs::read_dir(&release_dir).ok()?.find_map(|entry| {
        let path = entry.ok()?.path();
        let Some(file_name) = path.file_name().and_then(|f| f.to_str()) else {
            return None;
        };

        if file_name.starts_with("libquick") && path.extension().is_some_and(|ext| ext == "a") {
            Some(path)
        } else {
            None
        }
    })
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
                    kind: Error(line as u64, format!("Unexpected character: {current_char}")),
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
    tokens.push(Token {
        value: "EOF".to_string(),
        kind: Eof,
        line,
    });

    tokens
}

struct Allocation {
    ptr: *mut u8,
    layout: Layout,
    refs: usize,
}

pub struct Arena {
    allocations: Vec<Allocation>,
    index_map: HashMap<usize, usize>,
    _capacity_hint: usize,
}

impl Arena {
    fn new(cap: usize) -> Self {
        Self {
            allocations: Vec::new(),
            index_map: HashMap::new(),
            _capacity_hint: cap,
        }
    }

    fn alloc(&mut self, layout: std::alloc::Layout) -> Option<NonNull<u8>> {
        unsafe {
            let ptr = alloc(layout);
            let nn = NonNull::new(ptr)?;
            let idx = self.allocations.len();
            self.allocations.push(Allocation {
                ptr,
                layout,
                refs: 0,
            });
            self.index_map.insert(ptr as usize, idx);
            Some(nn)
        }
    }

    fn retain(&mut self, ptr: *mut u8) {
        if let Some(idx) = self.index_map.get(&(ptr as usize)).copied() {
            if let Some(alloc) = self.allocations.get_mut(idx) {
                alloc.refs = alloc.refs.saturating_add(1);
            }
        }
    }

    fn release_ref(&mut self, ptr: *mut u8) {
        if ptr.is_null() {
            return;
        }
        if let Some(idx) = self.index_map.get(&(ptr as usize)).copied() {
            if let Some(alloc) = self.allocations.get_mut(idx) {
                if alloc.refs > 0 {
                    alloc.refs -= 1;
                }
                if alloc.refs == 0 {
                    let layout = alloc.layout;
                    let raw_ptr = alloc.ptr;
                    self.allocations.swap_remove(idx);
                    if let Some(swapped) = self.allocations.get(idx) {
                        self.index_map.insert(swapped.ptr as usize, idx);
                    }
                    self.index_map.remove(&(raw_ptr as usize));
                    unsafe {
                        dealloc(raw_ptr, layout);
                    }
                }
            }
        }
    }

    fn mark(&self) -> usize {
        self.allocations.len()
    }

    fn release_from(&mut self, target_len: usize) {
        let mut retained: Vec<Allocation> = Vec::new();
        while self.allocations.len() > target_len {
            let alloc = self.allocations.pop().unwrap();
            self.index_map.remove(&(alloc.ptr as usize));
            if alloc.refs == 0 {
                unsafe {
                    dealloc(alloc.ptr, alloc.layout);
                }
            } else {
                retained.push(alloc);
            }
        }
        for alloc in retained.into_iter().rev() {
            let idx = self.allocations.len();
            self.index_map.insert(alloc.ptr as usize, idx);
            self.allocations.push(alloc);
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        for alloc in self.allocations.drain(..) {
            unsafe {
                dealloc(alloc.ptr, alloc.layout);
            }
        }
    }
}

#[cfg(test)]
mod ffi_safety_tests {
    use super::*;

    #[test]
    fn obj_insert_ignores_null_inputs() {
        unsafe {
            qs_obj_insert_str(std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut());
        }
    }

    #[test]
    fn obj_get_returns_null_on_null_inputs() {
        let ptr = unsafe { qs_obj_get_str(std::ptr::null_mut(), std::ptr::null()) };
        assert!(ptr.is_null());
    }
}
