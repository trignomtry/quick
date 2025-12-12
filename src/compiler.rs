use crate::*;
use inkwell::AddressSpace;
use inkwell::builder::{Builder, BuilderError};
use inkwell::context;
use inkwell::execution_engine::{ExecutionEngine, FunctionLookupError, JitFunction};
use inkwell::module::{Linkage, Module};
use inkwell::passes::PassBuilderOptions;
use inkwell::targets::{CodeModel, RelocMode, Target, TargetMachine};
use inkwell::OptimizationLevel;
use inkwell::types::{BasicType, BasicTypeEnum, FunctionType};
use inkwell::values::{
    BasicMetadataValueEnum, BasicValue as _, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};

pub struct Compiler<'ctx> {
    pub context: &'ctx context::Context,
    pub module: Module<'ctx>,
    pub builder: Builder<'ctx>,
    pub execution_engine: ExecutionEngine<'ctx>,
    pub instructions: Vec<Instruction>,
    pub vars: RefCell<HashMap<String, PointerValue<'ctx>>>,
    pub var_types: RefCell<HashMap<String, BasicTypeEnum<'ctx>>>,
    pub quick_var_types: RefCell<HashMap<String, Type>>,
    pub pctx: RefCell<PreCtx>,
    // Active module namespace during module function compilation
    pub current_module: RefCell<Option<String>>,
    // Captured environments for inline functions: closure name -> captured vars
    pub closure_envs: RefCell<HashMap<String, HashMap<String, CaptureDescriptor<'ctx>>>>,
    // Stack of function names currently being emitted
    pub current_function: RefCell<Vec<String>>,
    pub loop_stack: RefCell<Vec<LoopContext<'ctx>>>,
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

    fn get_or_add_function<F>(&self, name: &str, ctor: F) -> FunctionValue<'ctx>
    where
        F: FnOnce() -> FunctionType<'ctx>,
    {
        self.module
            .get_function(name)
            .unwrap_or_else(|| self.module.add_function(name, ctor(), None))
    }

    fn get_or_create_cstring(
        &self,
        global_name: &str,
        value: &str,
    ) -> Result<PointerValue<'ctx>, BuilderError> {
        if let Some(existing) = self.module.get_global(global_name) {
            Ok(existing.as_pointer_value())
        } else {
            self.builder
                .build_global_string_ptr(value, global_name)
                .map(|gv| gv.as_pointer_value())
        }
    }

    fn emit_struct_descriptor_registration(
        &self,
        _function: FunctionValue<'ctx>,
    ) -> Result<(), BuilderError> {
        let register_fn = self.get_or_create_qs_register_struct_descriptor();
        let register_enum_fn = self.get_or_create_qs_register_enum_variant();
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let ptr_ptr_ty = ptr_ty.ptr_type(AddressSpace::default());
        let i32_ty = self.context.i32_type();
        let i64_ty = self.context.i64_type();

        let sanitize = |name: &str| {
            name.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>()
        };

        let types_snapshot = self.pctx.borrow().types.clone();
        for (type_name, custype) in types_snapshot {
            match custype {
                Custype::Object(fields) => {
                    let field_count = fields.len();
                    let sanitized = sanitize(&type_name);

                    let canonical_ptr = self
                        .builder
                        .build_global_string_ptr(&type_name, &format!("json_type_name_{sanitized}"))?
                        .as_pointer_value();

                    let structural_signature = {
                        let ctx_ref = self.pctx.borrow();
                        ctx_ref.canonicalize_type(&Type::Custom(Custype::Object(fields.clone())))
                    };
                    let structural_ptr = self
                        .builder
                        .build_global_string_ptr(
                            &structural_signature,
                            &format!("json_type_sig_{sanitized}"),
                        )?
                        .as_pointer_value();

                    if field_count == 0 {
                        let count_val = i64_ty.const_int(0, false);
                        let null_ptr = ptr_ptr_ty.const_null();
                        self.builder.build_call(
                            register_fn,
                            &[
                                canonical_ptr.into(),
                                structural_ptr.into(),
                                count_val.into(),
                                null_ptr.into(),
                                null_ptr.into(),
                            ],
                            "reg_struct_empty",
                        )?;
                        continue;
                    }

                    let mut name_ptrs = Vec::with_capacity(field_count);
                    let mut type_ptrs = Vec::with_capacity(field_count);

                    for (index, (field_name, field_type)) in fields.iter().enumerate() {
                        let field_sanitized = format!("{sanitized}_{index}");
                        let field_ptr = self
                            .builder
                            .build_global_string_ptr(
                                field_name,
                                &format!("json_field_name_{field_sanitized}"),
                            )?
                            .as_pointer_value();
                        name_ptrs.push(field_ptr);

                        let field_signature = {
                            let ctx_ref = self.pctx.borrow();
                            ctx_ref.canonicalize_type(field_type)
                        };
                        let type_ptr = self
                            .builder
                            .build_global_string_ptr(
                                &field_signature,
                                &format!("json_field_type_{field_sanitized}"),
                            )?
                            .as_pointer_value();
                        type_ptrs.push(type_ptr);
                    }

                    let count_i32 = i32_ty.const_int(field_count as u64, false);
                    let names_alloca =
                        self.builder
                            .build_array_alloca(ptr_ty, count_i32, "json_field_names")?;
                    let types_alloca =
                        self.builder
                            .build_array_alloca(ptr_ty, count_i32, "json_field_types")?;

                    for (idx, ptr) in name_ptrs.iter().enumerate() {
                        let index_val = i32_ty.const_int(idx as u64, false);
                        let slot = unsafe {
                            self.builder.build_in_bounds_gep(
                                ptr_ty,
                                names_alloca,
                                &[index_val],
                                "json_name_slot",
                            )?
                        };
                        self.builder.build_store(slot, *ptr)?;
                    }

                    for (idx, ptr) in type_ptrs.iter().enumerate() {
                        let index_val = i32_ty.const_int(idx as u64, false);
                        let slot = unsafe {
                            self.builder.build_in_bounds_gep(
                                ptr_ty,
                                types_alloca,
                                &[index_val],
                                "json_type_slot",
                            )?
                        };
                        self.builder.build_store(slot, *ptr)?;
                    }

                    let names_ptr =
                        self.builder
                            .build_pointer_cast(names_alloca, ptr_ptr_ty, "json_names_ptr")?;
                    let types_ptr =
                        self.builder
                            .build_pointer_cast(types_alloca, ptr_ptr_ty, "json_types_ptr")?;

                    let count_val = i64_ty.const_int(field_count as u64, false);

                    self.builder.build_call(
                        register_fn,
                        &[
                            canonical_ptr.into(),
                            structural_ptr.into(),
                            count_val.into(),
                            names_ptr.into(),
                            types_ptr.into(),
                        ],
                        &format!("register_struct_{sanitized}"),
                    )?;
                }
                Custype::Enum(variants) => {
                    let sanitized = sanitize(&type_name);
                    let canonical_ptr = self
                        .builder
                        .build_global_string_ptr(&type_name, &format!("json_enum_name_{sanitized}"))?
                        .as_pointer_value();
                    let structural_signature = {
                        let ctx_ref = self.pctx.borrow();
                        ctx_ref.canonicalize_type(&Type::Custom(Custype::Enum(variants.clone())))
                    };
                    let structural_ptr = self
                        .builder
                        .build_global_string_ptr(
                            &structural_signature,
                            &format!("json_enum_sig_{sanitized}"),
                        )?
                        .as_pointer_value();

                    for (idx, variant) in variants.iter().enumerate() {
                        let variant_ptr = self
                            .builder
                            .build_global_string_ptr(
                                &variant.name,
                                &format!("json_enum_variant_{sanitized}_{idx}"),
                            )?
                            .as_pointer_value();

                        let payload_count = variant.payload.len();
                        let (payload_ptr_cast, count_val) = if payload_count == 0 {
                            (ptr_ptr_ty.const_null(), i64_ty.const_int(0, false))
                        } else {
                            let count_i32 = i32_ty.const_int(payload_count as u64, false);
                            let payload_alloca = self.builder.build_array_alloca(
                                ptr_ty,
                                count_i32,
                                &format!("json_enum_payload_{sanitized}_{idx}"),
                            )?;

                            for (pidx, payload_ty) in variant.payload.iter().enumerate() {
                                let payload_sig = {
                                    let ctx_ref = self.pctx.borrow();
                                    ctx_ref.canonicalize_type(payload_ty)
                                };
                                let payload_ptr = self
                                    .builder
                                    .build_global_string_ptr(
                                        &payload_sig,
                                        &format!("json_enum_payload_type_{sanitized}_{idx}_{pidx}"),
                                    )?
                                    .as_pointer_value();
                                let slot = unsafe {
                                    self.builder.build_in_bounds_gep(
                                        ptr_ty,
                                        payload_alloca,
                                        &[i32_ty.const_int(pidx as u64, false)],
                                        "json_enum_payload_slot",
                                    )?
                                };
                                self.builder.build_store(slot, payload_ptr)?;
                            }

                            let payload_ptr_cast = self
                                .builder
                                .build_pointer_cast(
                                    payload_alloca,
                                    ptr_ptr_ty,
                                    &format!("json_enum_payload_ptr_{sanitized}_{idx}"),
                                )?;
                            (payload_ptr_cast, i64_ty.const_int(payload_count as u64, false))
                        };

                        self.builder.build_call(
                            register_enum_fn,
                            &[
                                canonical_ptr.into(),
                                structural_ptr.into(),
                                variant_ptr.into(),
                                count_val.into(),
                                payload_ptr_cast.into(),
                            ],
                            &format!("register_enum_{sanitized}_{idx}"),
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Expose C rand() → i32
    fn get_or_create_rand(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("rand", || self.context.i32_type().fn_type(&[], false))
    }

    fn qtype_to_llvm(&self, t: &Type) -> BasicTypeEnum<'ctx> {
        match t {
            Type::GenericParam(name) => {
                panic!("Unresolved generic type parameter '{name}' reached LLVM lowering")
            }
            Type::Num => self.context.f64_type().as_basic_type_enum(),
            Type::Bool => self.context.bool_type().as_basic_type_enum(),
            Type::Never => {
                panic!("Type::Never has no direct LLVM representation");
            }
            Type::Str
            | Type::Custom(_)
            | Type::WebReturn
            | Type::Io
            | Type::RangeBuilder
            | Type::JsonValue
            | Type::Kv(_)
            | Type::List(_)
            | Type::Option(_)
            | Type::Result(_, _) => self
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

    fn lookup_enum_variant(&self, enum_name: &str, variant_name: &str) -> (usize, EnumVariant) {
        let binding = self.pctx.borrow();
        let Some(def) = binding.types.get(enum_name) else {
            panic!("Unknown enum '{enum_name}'");
        };
        let Custype::Enum(variants) = def else {
            panic!("Type '{enum_name}' is not an enum");
        };
        variants
            .iter()
            .enumerate()
            .find(|(_, variant)| variant.name == variant_name)
            .map(|(idx, variant)| (idx, variant.clone()))
            .unwrap_or_else(|| {
                panic!("Enum '{enum_name}' does not contain variant '{variant_name}'")
            })
    }

    fn enum_variants_for_type(&self, ty: &Type) -> Vec<EnumVariant> {
        match ty {
            Type::Custom(Custype::Enum(variants)) => variants.clone(),
            Type::Option(inner) => vec![
                EnumVariant {
                    name: "Some".to_string(),
                    payload: vec![(*inner.clone())],
                },
                EnumVariant {
                    name: "None".to_string(),
                    payload: vec![],
                },
            ],
            Type::Result(ok, err) => vec![
                EnumVariant {
                    name: "Ok".to_string(),
                    payload: vec![(*ok.clone())],
                },
                EnumVariant {
                    name: "Err".to_string(),
                    payload: vec![(*err.clone())],
                },
            ],
            other => panic!("Type {:?} is not an enum", other),
        }
    }

    fn adjust_enum_payload_value(
        &self,
        value: BasicValueEnum<'ctx>,
        expected: &Type,
        label: &str,
    ) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        match expected {
            Type::Num => match value {
                BasicValueEnum::FloatValue(_) => Ok(value),
                BasicValueEnum::IntValue(iv) => Ok(self
                    .builder
                    .build_signed_int_to_float(
                        iv,
                        self.context.f64_type(),
                        &format!("{label}_int_to_float"),
                    )?
                    .as_basic_value_enum()),
                other => panic!("Expected numeric payload, got {other:?}"),
            },
            Type::Bool => match value {
                BasicValueEnum::IntValue(iv) => {
                    if iv.get_type().get_bit_width() == 1 {
                        Ok(value)
                    } else {
                        let zero = iv.get_type().const_zero();
                        Ok(self
                            .builder
                            .build_int_compare(
                                IntPredicate::NE,
                                iv,
                                zero,
                                &format!("{label}_int_to_bool"),
                            )?
                            .as_basic_value_enum())
                    }
                }
                BasicValueEnum::FloatValue(fv) => {
                    let zero = self.context.f64_type().const_float(0.0);
                    Ok(self
                        .builder
                        .build_float_compare(
                            FloatPredicate::ONE,
                            fv,
                            zero,
                            &format!("{label}_float_to_bool"),
                        )?
                        .as_basic_value_enum())
                }
                other => panic!("Expected boolean payload, got {other:?}"),
            },
            _ => Ok(value),
        }
    }

    fn load_object_field_slot(
        &self,
        object_expr: &Expr,
        field: &str,
    ) -> (PointerValue<'ctx>, BasicValueEnum<'ctx>) {
        let base_val = self
            .compile_expr(object_expr)
            .unwrap_or_else(|e| panic!("Failed to compile object base: {e}"));
        let obj_ptr = match base_val {
            BasicValueEnum::PointerValue(p) => p,
            other => panic!("Property base must be a pointer, got {other:?}"),
        };

        let inferred_type = self
            .infer_expr_type(object_expr)
            .unwrap_or_else(|e| panic!("Unable to infer type for object field: {e}"));

        let custype = match inferred_type {
            Type::Custom(def @ Custype::Object(_)) => def,
            Type::Option(inner) => match *inner {
                Type::Custom(def @ Custype::Object(_)) => def,
                other => {
                    panic!("Field access on option whose inner type is not an object: {other:?}")
                }
            },
            other => panic!("Field access on non-object type: {other:?}"),
        };

        let (field_defs, type_name) = {
            let binding = self.pctx.borrow();
            let type_name = binding
                .types
                .iter()
                .find(|(_, def)| *def == &custype)
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| panic!("Unknown custom type for field '{field}'"));
            let Custype::Object(map) = binding
                .types
                .get(&type_name)
                .unwrap_or_else(|| panic!("Type '{type_name}' is not defined"))
            else {
                panic!("Type '{type_name}' is not an object");
            };
            (map.clone(), type_name)
        };

        let index = field_defs
            .keys()
            .position(|k| k == field)
            .unwrap_or_else(|| panic!("Field '{field}' not found on type '{type_name}'"));
        let idx_const = self.context.i64_type().const_int(index as u64, false);
        let slot_ptr = unsafe {
            self.builder
                .build_in_bounds_gep(
                    self.context.i64_type(),
                    obj_ptr,
                    &[idx_const],
                    &format!("field_slot_{field}"),
                )
                .unwrap()
        };

        let field_ty = field_defs
            .get(field)
            .cloned()
            .unwrap_or_else(|| panic!("Field '{field}' missing from type '{type_name}'"));
        let elem_basic = match field_ty.unwrap() {
            Type::Str
            | Type::List(_)
            | Type::Custom(_)
            | Type::Option(_)
            | Type::Result(_, _)
            | Type::Io
            | Type::WebReturn
            | Type::RangeBuilder
            | Type::JsonValue
            | Type::Kv(_)
            | Type::Function(_, _)
            | Type::Never => self
                .context
                .ptr_type(AddressSpace::default())
                .as_basic_type_enum(),
            Type::Num => self.context.f64_type().as_basic_type_enum(),
            Type::Bool => self.context.bool_type().as_basic_type_enum(),
            Type::Nil => self
                .context
                .ptr_type(AddressSpace::default())
                .as_basic_type_enum(),
            Type::GenericParam(name) => {
                panic!("Cannot access field '{field}' on unresolved generic '{name}'")
            }
        };

        let loaded = self
            .builder
            .build_load(elem_basic, slot_ptr, field)
            .unwrap();
        (slot_ptr, loaded)
    }

    fn emit_enum_variant(
        &self,
        enum_name: &str,
        variant_name: &str,
        payload_values: &[BasicValueEnum<'ctx>],
    ) -> Result<PointerValue<'ctx>, BuilderError> {
        let (variant_index, variant_def) = self.lookup_enum_variant(enum_name, variant_name);
        if variant_def.payload.len() != payload_values.len() {
            panic!(
                "Variant '{}.{}' expects {} argument(s), got {}",
                enum_name,
                variant_name,
                variant_def.payload.len(),
                payload_values.len()
            );
        }

        let slot_ty = self.context.ptr_type(AddressSpace::default());
        let slot_bytes = self
            .context
            .i64_type()
            .const_int(mem::size_of::<u64>() as u64, false);
        let slot_count = self
            .context
            .i64_type()
            .const_int((variant_def.payload.len() + 1) as u64, false);
        let total_bytes = self.builder.build_int_mul(
            slot_bytes,
            slot_count,
            &format!("enum_{}_{}_size", enum_name, variant_name),
        )?;
        let malloc_fn = self.get_or_create_malloc();
        let raw_ptr = self
            .builder
            .build_call(
                malloc_fn,
                &[total_bytes.into()],
                &format!("alloc_enum_{}_{}", enum_name, variant_name),
            )?
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();
        let enum_ptr = self.builder.build_pointer_cast(
            raw_ptr,
            slot_ty,
            &format!("enum_ptr_{}_{}", enum_name, variant_name),
        )?;

        let i64_ty = self.context.i64_type();
        let tag_ptr = unsafe {
            self.builder.build_in_bounds_gep(
                i64_ty,
                enum_ptr,
                &[i64_ty.const_int(0, false)],
                &format!("enum_tag_ptr_{}_{}", enum_name, variant_name),
            )?
        };
        self.builder.build_store(
            tag_ptr,
            i64_ty
                .const_int(variant_index as u64, false)
                .as_basic_value_enum(),
        )?;

        for (slot_idx, (payload_ty, raw_value)) in variant_def
            .payload
            .iter()
            .zip(payload_values.iter())
            .enumerate()
        {
            let adjusted = self.adjust_enum_payload_value(
                *raw_value,
                payload_ty,
                &format!("enum_payload_cast_{enum_name}_{variant_name}_{slot_idx}"),
            )?;
            let payload_ptr = unsafe {
                self.builder.build_in_bounds_gep(
                    i64_ty,
                    enum_ptr,
                    &[i64_ty.const_int((slot_idx + 1) as u64, false)],
                    &format!("enum_payload_ptr_{enum_name}_{variant_name}_{slot_idx}"),
                )?
            };
            self.builder.build_store(payload_ptr, adjusted)?;
        }

        Ok(enum_ptr)
    }

    fn result_struct_type(&self) -> inkwell::types::StructType<'ctx> {
        self.context.struct_type(
            &[
                self.context.bool_type().as_basic_type_enum(),
                self.context
                    .ptr_type(AddressSpace::default())
                    .as_basic_type_enum(),
                self.context
                    .ptr_type(AddressSpace::default())
                    .as_basic_type_enum(),
            ],
            false,
        )
    }

    fn lower_result_variant(
        &self,
        expr: &Expr,
        payload: BasicValueEnum<'ctx>,
        is_ok: bool,
    ) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        let result_ty = self
            .infer_expr_type(expr)
            .unwrap_or_else(|e| panic!("Unable to infer type for Result expression: {e}"));
        let (ok_ty, err_ty) = match &result_ty {
            Type::Result(ok, err) => (ok.as_ref(), err.as_ref()),
            other => panic!("Expected Result type for expression, found {other:?}"),
        };

        let payload_type = if is_ok { ok_ty } else { err_ty };
        let payload_llvm = self.qtype_to_llvm(payload_type);
        if !matches!(payload_llvm, BasicTypeEnum::PointerType(_)) {
            panic!("Result payloads must lower to pointer types, got {payload_type:?}");
        }

        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let struct_ty = self.result_struct_type();

        let size_val = struct_ty
            .size_of()
            .unwrap_or_else(|| panic!("Failed to compute Result struct size"));
        let malloc_fn = self.get_or_create_malloc();
        let raw_ptr = self
            .builder
            .build_call(malloc_fn, &[size_val.into()], "result_malloc")?
            .try_as_basic_value()
            .left()
            .unwrap()
            .into_pointer_value();
        let typed_ptr = self.builder.build_pointer_cast(
            raw_ptr,
            struct_ty.ptr_type(AddressSpace::default()),
            "result_ptr",
        )?;

        let tag_ptr = self
            .builder
            .build_struct_gep(struct_ty, typed_ptr, 0, "result_tag_ptr")?;
        let ok_slot = self
            .builder
            .build_struct_gep(struct_ty, typed_ptr, 1, "result_ok_slot")?;
        let err_slot = self
            .builder
            .build_struct_gep(struct_ty, typed_ptr, 2, "result_err_slot")?;

        let tag_val = self
            .context
            .bool_type()
            .const_int(if is_ok { 1 } else { 0 }, false);
        self.builder.build_store(tag_ptr, tag_val)?;

        let payload_ptr = match payload {
            BasicValueEnum::PointerValue(ptr) => ptr,
            other => panic!("Result payload must be pointer-like, got {other:?}"),
        };

        let erased_payload = self.builder.build_pointer_cast(
            payload_ptr,
            ptr_ty,
            if is_ok {
                "result_ok_cast"
            } else {
                "result_err_cast"
            },
        )?;

        let null_ptr = ptr_ty.const_null();
        if is_ok {
            if matches!(ok_ty, Type::Never) {
                panic!("Result::Ok produced but Ok type inferred as Never");
            }
            self.builder.build_store(ok_slot, erased_payload)?;
            self.builder.build_store(err_slot, null_ptr)?;
        } else {
            if matches!(err_ty, Type::Never) {
                panic!("Result::Err produced but Err type inferred as Never");
            }
            self.builder.build_store(ok_slot, null_ptr)?;
            self.builder.build_store(err_slot, erased_payload)?;
        }

        let erased = self
            .builder
            .build_pointer_cast(typed_ptr, ptr_ty, "result_ptr_erased")?;
        Ok(erased.as_basic_value_enum())
    }

    fn lower_option_force(
        &self,
        option_expr: &Expr,
        message_ptr: PointerValue<'ctx>,
        label: &str,
    ) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        let option_type = self
            .infer_expr_type(option_expr)
            .unwrap_or_else(|e| panic!("Type error: {e}"));
        let Type::Option(_) = option_type else {
            panic!("Option::{label} called on non Option type");
        };

        let option_val = self.compile_expr(option_expr)?;
        let zero_float = self.context.f64_type().const_float(0.0);
        let zero_int = self.context.i64_type().const_zero();

        let parent_fn = self
            .builder
            .get_insert_block()
            .and_then(|bb| bb.get_parent())
            .expect("Option helper must be inside a function");

        let ok_block = self
            .context
            .append_basic_block(parent_fn, &format!("option.{label}.some"));
        let err_block = self
            .context
            .append_basic_block(parent_fn, &format!("option.{label}.none"));
        let cont_block = self
            .context
            .append_basic_block(parent_fn, &format!("option.{label}.cont"));

        match option_val {
            BasicValueEnum::PointerValue(ptr) => {
                let cond = self
                    .builder
                    .build_is_not_null(ptr, &format!("option_{label}_has_value"))?;
                self.builder
                    .build_conditional_branch(cond, ok_block, err_block)?;

                self.builder.position_at_end(ok_block);
                self.builder.build_unconditional_branch(cont_block)?;

                self.builder.position_at_end(err_block);
                let panic_fn = self.get_or_create_qs_panic();
                self.builder.build_call(
                    panic_fn,
                    &[message_ptr.into()],
                    &format!("option_{label}_panic"),
                )?;
                self.builder.build_unreachable()?;

                self.builder.position_at_end(cont_block);
                Ok(ptr.as_basic_value_enum())
            }
            BasicValueEnum::FloatValue(fv) => {
                let cond = self.builder.build_float_compare(
                    FloatPredicate::ONE,
                    fv,
                    zero_float,
                    &format!("option_{label}_has_value"),
                )?;
                self.builder
                    .build_conditional_branch(cond, ok_block, err_block)?;

                self.builder.position_at_end(ok_block);
                self.builder.build_unconditional_branch(cont_block)?;

                self.builder.position_at_end(err_block);
                let panic_fn = self.get_or_create_qs_panic();
                self.builder.build_call(
                    panic_fn,
                    &[message_ptr.into()],
                    &format!("option_{label}_panic"),
                )?;
                self.builder.build_unreachable()?;

                self.builder.position_at_end(cont_block);
                Ok(fv.as_basic_value_enum())
            }
            BasicValueEnum::IntValue(iv) => {
                let cond = self.builder.build_int_compare(
                    IntPredicate::NE,
                    iv,
                    zero_int,
                    &format!("option_{label}_has_value"),
                )?;
                self.builder
                    .build_conditional_branch(cond, ok_block, err_block)?;

                self.builder.position_at_end(ok_block);
                self.builder.build_unconditional_branch(cont_block)?;

                self.builder.position_at_end(err_block);
                let panic_fn = self.get_or_create_qs_panic();
                self.builder.build_call(
                    panic_fn,
                    &[message_ptr.into()],
                    &format!("option_{label}_panic"),
                )?;
                self.builder.build_unreachable()?;

                self.builder.position_at_end(cont_block);
                Ok(iv.as_basic_value_enum())
            }
            other => panic!("Option::{label} is not implemented for {other:?}"),
        }
    }

    fn lower_result_force(
        &self,
        result_expr: &Expr,
        expect_ok: bool,
        message_ptr: PointerValue<'ctx>,
        label: &str,
    ) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        let result_type = self
            .infer_expr_type(result_expr)
            .unwrap_or_else(|e| panic!("Type error: {e}"));
        let Type::Result(ok_ty, err_ty) = result_type else {
            panic!("Result::{label} called on non Result type");
        };

        let target_ty = if expect_ok { ok_ty } else { err_ty };
        let llvm_target = self.qtype_to_llvm(&target_ty);
        let BasicTypeEnum::PointerType(expected_ptr_ty) = llvm_target else {
            panic!("Result::{label} is only implemented for pointer payloads");
        };

        let result_val = self.compile_expr(result_expr)?;
        let (tag, ok_slot, err_slot) =
            self.project_result_slots(result_val, &format!("result_{label}"))?;

        let cond = if expect_ok {
            tag
        } else {
            self.builder
                .build_not(tag, &format!("result_{label}_expect_err"))?
        };

        let parent_fn = self
            .builder
            .get_insert_block()
            .and_then(|bb| bb.get_parent())
            .expect("Result helper must be inside a function");
        let good_block = self
            .context
            .append_basic_block(parent_fn, &format!("result.{label}.match"));
        let bad_block = self
            .context
            .append_basic_block(parent_fn, &format!("result.{label}.panic"));
        let cont_block = self
            .context
            .append_basic_block(parent_fn, &format!("result.{label}.cont"));

        let result_alloca = self
            .builder
            .build_alloca(expected_ptr_ty, &format!("result_{label}_slot"))?;
        let ptr_ty = self.context.ptr_type(AddressSpace::default());

        self.builder
            .build_conditional_branch(cond, good_block, bad_block)?;

        self.builder.position_at_end(good_block);
        let slot = if expect_ok { ok_slot } else { err_slot };
        let raw_payload = self
            .builder
            .build_load(ptr_ty, slot, &format!("result_{label}_raw_payload"))?
            .into_pointer_value();
        let casted = self.builder.build_pointer_cast(
            raw_payload,
            expected_ptr_ty,
            &format!("result_{label}_payload_cast"),
        )?;
        self.builder
            .build_store(result_alloca, BasicValueEnum::PointerValue(casted))?;
        self.builder.build_unconditional_branch(cont_block)?;

        self.builder.position_at_end(bad_block);
        let panic_fn = self.get_or_create_qs_panic();
        self.builder.build_call(
            panic_fn,
            &[message_ptr.into()],
            &format!("result_{label}_panic"),
        )?;
        self.builder.build_unreachable()?;

        self.builder.position_at_end(cont_block);
        let loaded = self.builder.build_load(
            expected_ptr_ty,
            result_alloca,
            &format!("result_{label}_loaded"),
        )?;
        Ok(loaded)
    }

    fn option_predicate(
        &self,
        option_val: BasicValueEnum<'ctx>,
        expect_some: bool,
        label: &str,
    ) -> Result<IntValue<'ctx>, BuilderError> {
        let predicate = match option_val {
            BasicValueEnum::PointerValue(ptr) => self
                .builder
                .build_is_not_null(ptr, &format!("{label}_not_null"))?,
            BasicValueEnum::FloatValue(fv) => {
                let zero = self.context.f64_type().const_float(0.0);
                self.builder.build_float_compare(
                    FloatPredicate::ONE,
                    fv,
                    zero,
                    &format!("{label}_non_zero"),
                )?
            }
            BasicValueEnum::IntValue(iv) => {
                let zero = iv.get_type().const_zero();
                self.builder.build_int_compare(
                    IntPredicate::NE,
                    iv,
                    zero,
                    &format!("{label}_non_zero"),
                )?
            }
            other => panic!("Option predicate not implemented for representation: {other:?}"),
        };
        if expect_some {
            Ok(predicate)
        } else {
            Ok(self
                .builder
                .build_not(predicate, &format!("{label}_inverted"))?)
        }
    }

    fn project_result_slots(
        &self,
        result_val: BasicValueEnum<'ctx>,
        label: &str,
    ) -> Result<(IntValue<'ctx>, PointerValue<'ctx>, PointerValue<'ctx>), BuilderError> {
        let result_ptr = match result_val {
            BasicValueEnum::PointerValue(p) => p,
            other => panic!("Result value must be a pointer, got {other:?}"),
        };
        let struct_ty = self.result_struct_type();
        let typed_ptr = self.builder.build_pointer_cast(
            result_ptr,
            struct_ty.ptr_type(AddressSpace::default()),
            &format!("{label}_struct_ptr"),
        )?;
        let tag_ptr =
            self.builder
                .build_struct_gep(struct_ty, typed_ptr, 0, &format!("{label}_tag_ptr"))?;
        let ok_slot =
            self.builder
                .build_struct_gep(struct_ty, typed_ptr, 1, &format!("{label}_ok_slot"))?;
        let err_slot =
            self.builder
                .build_struct_gep(struct_ty, typed_ptr, 2, &format!("{label}_err_slot"))?;
        let tag_val = self
            .builder
            .build_load(self.context.bool_type(), tag_ptr, &format!("{label}_tag"))?
            .into_int_value();
        Ok((tag_val, ok_slot, err_slot))
    }

    fn load_enum_slot(
        &self,
        enum_ptr: PointerValue<'ctx>,
        slot_index: usize,
        ty: &Type,
        label: &str,
    ) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        let i64_ty = self.context.i64_type();
        let offset = i64_ty.const_int(slot_index as u64, false);
        let slot_ptr = unsafe {
            self.builder.build_in_bounds_gep(
                i64_ty,
                enum_ptr,
                &[offset],
                &format!("{label}_ptr"),
            )?
        };
        let llvm_ty = self.qtype_to_llvm(ty);
        Ok(self
            .builder
            .build_load(llvm_ty, slot_ptr, &format!("{label}_load"))?)
    }

    fn build_value_equality(
        &self,
        left: BasicValueEnum<'ctx>,
        right: BasicValueEnum<'ctx>,
        ty: &Type,
        label: &str,
    ) -> Result<IntValue<'ctx>, BuilderError> {
        match ty {
            Type::Num => {
                let left_f = match left {
                    BasicValueEnum::FloatValue(fv) => fv,
                    BasicValueEnum::IntValue(iv) => self.builder.build_signed_int_to_float(
                        iv,
                        self.context.f64_type(),
                        &format!("{label}_lhs_to_float"),
                    )?,
                    other => panic!("Cannot compare {other:?} as number"),
                };
                let right_f = match right {
                    BasicValueEnum::FloatValue(fv) => fv,
                    BasicValueEnum::IntValue(iv) => self.builder.build_signed_int_to_float(
                        iv,
                        self.context.f64_type(),
                        &format!("{label}_rhs_to_float"),
                    )?,
                    other => panic!("Cannot compare {other:?} as number"),
                };
                self.builder
                    .build_float_compare(FloatPredicate::OEQ, left_f, right_f, label)
            }
            Type::Bool => {
                let as_bool = |builder: &Builder<'ctx>,
                               val: BasicValueEnum<'ctx>,
                               suffix: &str|
                 -> Result<IntValue<'ctx>, BuilderError> {
                    match val {
                        BasicValueEnum::IntValue(iv) => {
                            if iv.get_type().get_bit_width() == 1 {
                                Ok(iv)
                            } else {
                                let zero = iv.get_type().const_zero();
                                builder.build_int_compare(IntPredicate::NE, iv, zero, suffix)
                            }
                        }
                        BasicValueEnum::FloatValue(fv) => {
                            let zero = self.context.f64_type().const_float(0.0);
                            builder.build_float_compare(FloatPredicate::ONE, fv, zero, suffix)
                        }
                        other => panic!("Cannot convert {other:?} to bool for comparison"),
                    }
                };
                let lhs = as_bool(&self.builder, left, &format!("{label}_lhs_bool"))?;
                let rhs = as_bool(&self.builder, right, &format!("{label}_rhs_bool"))?;
                self.builder
                    .build_int_compare(IntPredicate::EQ, lhs, rhs, label)
            }
            Type::Str => {
                let strcmp_fn = self.get_or_create_strcmp();
                let call = self.builder.build_call(
                    strcmp_fn,
                    &[left.into(), right.into()],
                    &format!("{label}_strcmp"),
                )?;
                let cmp = call.try_as_basic_value().left().unwrap().into_int_value();
                let zero = self.context.i32_type().const_int(0, false);
                self.builder
                    .build_int_compare(IntPredicate::EQ, cmp, zero, label)
            }
            other => panic!("Equality for type {other:?} is not implemented"),
        }
    }

    fn declare_local_binding(
        &self,
        function: FunctionValue<'ctx>,
        name: &str,
        value: BasicValueEnum<'ctx>,
        ty: &Type,
    ) -> Result<(), BuilderError> {
        let entry = function.get_first_basic_block().unwrap();
        let temp_builder = self.context.create_builder();
        match entry.get_first_instruction() {
            Some(inst) => temp_builder.position_before(&inst),
            None => temp_builder.position_at_end(entry),
        }
        let ptr = temp_builder.build_alloca(value.get_type(), name)?;
        self.builder.build_store(ptr, value)?;
        self.vars.borrow_mut().insert(name.to_string(), ptr);
        self.var_types
            .borrow_mut()
            .insert(name.to_string(), value.get_type());
        self.quick_var_types
            .borrow_mut()
            .insert(name.to_string(), ty.clone());
        Ok(())
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

        let param_metadata_types: Vec<BasicMetadataTypeEnum> = params
            .iter()
            .map(|(_, ty)| self.qtype_to_llvm(ty).into())
            .collect();

        let fn_type = if *return_type == Type::Never {
            self.context
                .void_type()
                .fn_type(&param_metadata_types, false)
        } else {
            let llvm_ret_type = self.qtype_to_llvm(return_type);
            match llvm_ret_type {
                BasicTypeEnum::IntType(int_ty) => int_ty.fn_type(&param_metadata_types, false),
                BasicTypeEnum::PointerType(ptr_ty) => ptr_ty.fn_type(&param_metadata_types, false),
                BasicTypeEnum::FloatType(float_ty) => {
                    float_ty.fn_type(&param_metadata_types, false)
                }
                BasicTypeEnum::ArrayType(array_ty) => {
                    array_ty.fn_type(&param_metadata_types, false)
                }
                BasicTypeEnum::ScalableVectorType(vec_ty) => {
                    vec_ty.fn_type(&param_metadata_types, false)
                }
                BasicTypeEnum::VectorType(vec_ty) => vec_ty.fn_type(&param_metadata_types, false),
                BasicTypeEnum::StructType(struct_ty) => {
                    struct_ty.fn_type(&param_metadata_types, false)
                }
            }
        };

        self.module.add_function(name, fn_type, None)
    }

    // Module functions are compiled in run_code by synthesizing namespaced
    // Instruction::FunctionDef entries and feeding them through compile_instruction.

    pub fn run_code(&self) -> Option<JitFunction<'_, SumFunc>> {
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
                let (saved_types, saved_generic_types, saved_describers) = {
                    let pctx_ref = self.pctx.borrow();
                    (
                        pctx_ref.types.clone(),
                        pctx_ref.generic_types.clone(),
                        pctx_ref.deserialize_registry.clone(),
                    )
                };
                {
                    let mut pctx_mut = self.pctx.borrow_mut();
                    for (ty_name, custype) in &minfo.types {
                        pctx_mut
                            .types
                            .entry(ty_name.clone())
                            .or_insert(custype.clone());
                    }
                    for (ty_name, template) in &minfo.generic_types {
                        pctx_mut
                            .generic_types
                            .entry(ty_name.clone())
                            .or_insert(template.clone());
                    }
                    for (sig, descriptor) in &minfo.deserialize_plans {
                        pctx_mut
                            .deserialize_registry
                            .entry(sig.clone())
                            .or_insert(descriptor.clone());
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

                let mut pctx_restore = self.pctx.borrow_mut();
                pctx_restore.types = saved_types;
                pctx_restore.generic_types = saved_generic_types;
                pctx_restore.deserialize_registry = saved_describers;
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

        self.emit_struct_descriptor_registration(main_fn).unwrap();

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

        // Run a full aggressive optimization pipeline over the module so hot loops shed allocas and dead code.
        {
            let target_triple = TargetMachine::get_default_triple();
            let target = Target::from_triple(&target_triple)
                .expect("Failed to look up native target for optimization");
            let target_machine = target
                .create_target_machine(
                    &target_triple,
                    "generic",
                    "",
                    OptimizationLevel::Aggressive,
                    RelocMode::Default,
                    CodeModel::Default,
                )
                .expect("Failed to create native target machine for optimization");

            let pass_opts = PassBuilderOptions::create();
            // default<O3> mirrors opt -O3 with the new pass manager
            if let Err(err) = self
                .module
                .run_passes("default<O3>", &target_machine, pass_opts)
            {
                eprintln!("LLVM optimization pipeline failed: {err}");
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
        let option_unwrap_fn = self.get_or_create_option_unwrap();
        self.execution_engine
            .add_global_mapping(&option_unwrap_fn, qs_option_unwrap as usize);
        let result_unwrap_fn = self.get_or_create_result_unwrap();
        self.execution_engine
            .add_global_mapping(&result_unwrap_fn, qs_result_unwrap as usize);
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
        let list_join_fn = self.get_or_create_list_join();
        self.execution_engine
            .add_global_mapping(&list_join_fn, qs_list_join as usize);
        let sprintf_fn = self.get_or_create_sprintf();
        self.execution_engine
            .add_global_mapping(&sprintf_fn, sprintf as usize);
        let rand_fn = self.get_or_create_rand();
        self.execution_engine
            .add_global_mapping(&rand_fn, rand as usize);
        let exit_fn = self.get_or_create_io_exit();
        self.execution_engine
            .add_global_mapping(&exit_fn, io_exit as usize);

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
        let panic_fn = self.get_or_create_qs_panic();
        self.execution_engine
            .add_global_mapping(&panic_fn, qs_panic as usize);
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
        let web_file_not_found_fn = self.get_or_create_web_file_not_found();
        self.execution_engine
            .add_global_mapping(&web_file_not_found_fn, web_file_not_found as usize);
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

        let register_desc_fn = self.get_or_create_qs_register_struct_descriptor();
        self.execution_engine
            .add_global_mapping(&register_desc_fn, qs_register_struct_descriptor as usize);
        let register_enum_fn = self.get_or_create_qs_register_enum_variant();
        self.execution_engine
            .add_global_mapping(&register_enum_fn, qs_register_enum_variant as usize);
        let struct_from_json_fn = self.get_or_create_qs_struct_from_json();
        self.execution_engine
            .add_global_mapping(&struct_from_json_fn, qs_struct_from_json as usize);
        let enum_from_json_fn = self.get_or_create_qs_enum_from_json();
        self.execution_engine
            .add_global_mapping(&enum_from_json_fn, qs_enum_from_json as usize);
        let struct_to_json_fn = self.get_or_create_qs_struct_to_json();
        self.execution_engine
            .add_global_mapping(&struct_to_json_fn, qs_struct_to_json as usize);
        let json_parse_fn = self.get_or_create_qs_json_parse();
        self.execution_engine
            .add_global_mapping(&json_parse_fn, qs_json_parse as usize);
        let json_stringify_fn = self.get_or_create_qs_json_stringify();
        self.execution_engine
            .add_global_mapping(&json_stringify_fn, qs_json_stringify as usize);
        let json_is_null_fn = self.get_or_create_qs_json_is_null();
        self.execution_engine
            .add_global_mapping(&json_is_null_fn, qs_json_is_null as usize);
        let json_len_fn = self.get_or_create_qs_json_len();
        self.execution_engine
            .add_global_mapping(&json_len_fn, qs_json_len as usize);
        let json_get_fn = self.get_or_create_qs_json_get();
        self.execution_engine
            .add_global_mapping(&json_get_fn, qs_json_get as usize);
        let json_index_fn = self.get_or_create_qs_json_index();
        self.execution_engine
            .add_global_mapping(&json_index_fn, qs_json_index as usize);
        let json_str_fn = self.get_or_create_qs_json_str();
        self.execution_engine
            .add_global_mapping(&json_str_fn, qs_json_str as usize);

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
            Instruction::Expr(expr, _expr_type) => {
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
                    if function.get_type().get_return_type().is_some() {
                        self.builder.build_return(Some(&ret_val))?;
                    } else {
                        self.builder.build_return(None)?;
                    }
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

                enum MatchKind {
                    NeedsCatchAll,
                    Bool,
                    Enum {
                        enum_type: Type,
                        variants: Vec<String>,
                    },
                }

                let match_kind = match scrutinee_type.clone() {
                    Type::Num | Type::Str => MatchKind::NeedsCatchAll,
                    Type::Bool => MatchKind::Bool,
                    other => {
                        let variants = self.enum_variants_for_type(&other);
                        MatchKind::Enum {
                            enum_type: other.clone(),
                            variants: variants
                                .iter()
                                .map(|variant| variant.name.clone())
                                .collect(),
                        }
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
                        MatchArm::EnumDestructure { variant, .. } => {
                            seen_variants.insert(variant.clone());
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
                            eprintln!(
                                "All variants of {scrutinee_type:?} not covered in match statement"
                            );
                            std::process::exit(70);
                        }
                    }
                    MatchKind::Bool => {
                        if !saw_catchall && !(saw_true && saw_false) {
                            eprintln!(
                                "Boolean match must handle both true and false or provide a catch-all arm"
                            );
                            std::process::exit(70);
                        }
                    }
                    MatchKind::Enum { variants, .. } => {
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
                let scrutinee_value = self.compile_expr(expr)?;
                let mut current_block = self.builder.get_insert_block().unwrap();
                let after_block = self.context.append_basic_block(function, "match.after");

                for (idx, arm) in arms.iter().enumerate() {
                    let arm_block = self
                        .context
                        .append_basic_block(function, &format!("match.arm.{idx}"));
                    let next_block = if idx == arms.len() - 1 {
                        after_block
                    } else {
                        self.context
                            .append_basic_block(function, &format!("match.next.{idx}"))
                    };

                    self.builder.position_at_end(current_block);

                    match arm {
                        MatchArm::Literal(pattern, runs) => {
                            let pattern_val = self.compile_expr(pattern)?;
                            let cond = self.build_value_equality(
                                scrutinee_value,
                                pattern_val,
                                &scrutinee_type,
                                &format!("match_literal_cond_{idx}"),
                            )?;
                            self.builder
                                .build_conditional_branch(cond, arm_block, next_block)?;

                            self.builder.position_at_end(arm_block);
                            self.compile_instruction(function, runs)?;
                            if self
                                .builder
                                .get_insert_block()
                                .unwrap()
                                .get_terminator()
                                .is_none()
                            {
                                self.builder.build_unconditional_branch(after_block)?;
                            }
                        }
                        MatchArm::EnumDestructure {
                            enum_name,
                            enum_type,
                            variant,
                            patterns,
                            body,
                        } => match enum_type {
                            Type::Option(inner_ty) => {
                                let cond = if variant == "Some" {
                                    self.option_predicate(
                                        scrutinee_value,
                                        true,
                                        &format!("match_option_some_{idx}"),
                                    )?
                                } else if variant == "None" {
                                    self.option_predicate(
                                        scrutinee_value,
                                        false,
                                        &format!("match_option_none_{idx}"),
                                    )?
                                } else {
                                    panic!("Unknown Option variant '{variant}'");
                                };

                                self.builder
                                    .build_conditional_branch(cond, arm_block, next_block)?;

                                self.builder.position_at_end(arm_block);
                                let mut bound_names = Vec::new();

                                if variant == "Some" {
                                    if patterns.len() != 1 {
                                        panic!("Option::Some pattern expects exactly one binding");
                                    }
                                    match &patterns[0] {
                                        EnumPattern::Binding(binding_name) => {
                                            self.declare_local_binding(
                                                function,
                                                binding_name,
                                                scrutinee_value,
                                                &*inner_ty.clone(),
                                            )?;
                                            bound_names.push(binding_name.clone());
                                        }
                                        EnumPattern::Literal(_) => {
                                            panic!(
                                                "Option::Some pattern currently supports only variable bindings"
                                            );
                                        }
                                    }
                                } else if !patterns.is_empty() {
                                    panic!("Option::None pattern cannot bind values");
                                }

                                self.compile_instruction(function, body)?;
                                if self
                                    .builder
                                    .get_insert_block()
                                    .unwrap()
                                    .get_terminator()
                                    .is_none()
                                {
                                    self.builder.build_unconditional_branch(after_block)?;
                                }
                                for name in bound_names {
                                    self.vars.borrow_mut().remove(&name);
                                    self.var_types.borrow_mut().remove(&name);
                                    self.quick_var_types.borrow_mut().remove(&name);
                                }
                            }
                            Type::Result(ok_ty, err_ty) => {
                                let result_ptr = match scrutinee_value {
                                    BasicValueEnum::PointerValue(ptr) => ptr,
                                    other => panic!(
                                        "Result match expects pointer scrutinee, found {other:?}"
                                    ),
                                };
                                let struct_ty = self.result_struct_type();
                                let typed_ptr = self.builder.build_pointer_cast(
                                    result_ptr,
                                    struct_ty.ptr_type(AddressSpace::default()),
                                    &format!("result_match_ptr_{idx}"),
                                )?;

                                let tag_ptr = self.builder.build_struct_gep(
                                    struct_ty,
                                    typed_ptr,
                                    0,
                                    &format!("result_tag_ptr_{idx}"),
                                )?;
                                let tag_val = self
                                    .builder
                                    .build_load(
                                        self.context.bool_type().as_basic_type_enum(),
                                        tag_ptr,
                                        &format!("result_tag_val_{idx}"),
                                    )?
                                    .into_int_value();
                                let expected = if variant == "Ok" {
                                    self.context.bool_type().const_int(1, false)
                                } else if variant == "Err" {
                                    self.context.bool_type().const_int(0, false)
                                } else {
                                    panic!("Unknown Result variant '{variant}'");
                                };
                                let cond = self.builder.build_int_compare(
                                    IntPredicate::EQ,
                                    tag_val,
                                    expected,
                                    &format!("result_tag_cmp_{idx}"),
                                )?;
                                self.builder
                                    .build_conditional_branch(cond, arm_block, next_block)?;

                                self.builder.position_at_end(arm_block);
                                let mut bound_names = Vec::new();

                                let slot_index = if variant == "Ok" { 1 } else { 2 };
                                let slot_ptr = self.builder.build_struct_gep(
                                    struct_ty,
                                    typed_ptr,
                                    slot_index,
                                    &format!("result_payload_slot_{idx}"),
                                )?;
                                let raw_payload = self
                                    .builder
                                    .build_load(
                                        self.context
                                            .ptr_type(AddressSpace::default())
                                            .as_basic_type_enum(),
                                        slot_ptr,
                                        &format!("result_payload_raw_{idx}"),
                                    )?
                                    .into_pointer_value();

                                let payload_ty = if variant == "Ok" {
                                    *ok_ty.clone()
                                } else {
                                    *err_ty.clone()
                                };

                                if !patterns.is_empty() {
                                    if patterns.len() != 1 {
                                        panic!(
                                            "Result pattern for '{variant}' expects exactly one binding"
                                        );
                                    }
                                    match &patterns[0] {
                                        EnumPattern::Binding(binding_name) => {
                                            let target_ptr_ty = match self
                                                .qtype_to_llvm(&payload_ty)
                                            {
                                                BasicTypeEnum::PointerType(ptr) => ptr,
                                                other => panic!(
                                                    "Result payload must be pointer type, got {other:?}"
                                                ),
                                            };
                                            let typed_payload = self.builder.build_pointer_cast(
                                                raw_payload,
                                                target_ptr_ty,
                                                &format!("result_payload_cast_{idx}"),
                                            )?;
                                            self.declare_local_binding(
                                                function,
                                                binding_name,
                                                typed_payload.as_basic_value_enum(),
                                                &payload_ty,
                                            )?;
                                            bound_names.push(binding_name.clone());
                                        }
                                        EnumPattern::Literal(_) => {
                                            panic!(
                                                "Result patterns currently support only variable bindings"
                                            );
                                        }
                                    }
                                }

                                self.compile_instruction(function, body)?;
                                if self
                                    .builder
                                    .get_insert_block()
                                    .unwrap()
                                    .get_terminator()
                                    .is_none()
                                {
                                    self.builder.build_unconditional_branch(after_block)?;
                                }
                                for name in bound_names {
                                    self.vars.borrow_mut().remove(&name);
                                    self.var_types.borrow_mut().remove(&name);
                                    self.quick_var_types.borrow_mut().remove(&name);
                                }
                            }
                            Type::Custom(Custype::Enum(_)) => {
                                let enum_ptr = match scrutinee_value {
                                    BasicValueEnum::PointerValue(ptr) => ptr,
                                    other => panic!(
                                        "Enum match expects pointer scrutinee, found {other:?}"
                                    ),
                                };
                                let (variant_index, variant_def) =
                                    self.lookup_enum_variant(enum_name, variant);
                                let payload_types = variant_def.payload.clone();
                                let i64_ty = self.context.i64_type();
                                let tag_ptr = unsafe {
                                    self.builder.build_in_bounds_gep(
                                        i64_ty,
                                        enum_ptr,
                                        &[i64_ty.const_int(0, false)],
                                        &format!("match_tag_ptr_{idx}"),
                                    )?
                                };
                                let tag_val = self
                                    .builder
                                    .build_load(
                                        i64_ty.as_basic_type_enum(),
                                        tag_ptr,
                                        &format!("match_tag_load_{idx}"),
                                    )?
                                    .into_int_value();
                                let expected_tag = i64_ty.const_int(variant_index as u64, false);
                                let mut cond = self.builder.build_int_compare(
                                    IntPredicate::EQ,
                                    tag_val,
                                    expected_tag,
                                    &format!("match_tag_cmp_{idx}"),
                                )?;

                                for (slot_idx, pattern) in patterns.iter().enumerate() {
                                    if let EnumPattern::Literal(expected_expr) = pattern {
                                        let payload_ty = &payload_types[slot_idx];
                                        let payload_val = self.load_enum_slot(
                                            enum_ptr,
                                            slot_idx + 1,
                                            payload_ty,
                                            &format!("enum_payload_{idx}_{slot_idx}"),
                                        )?;
                                        let expected_val = self.compile_expr(expected_expr)?;
                                        let payload_eq = self.build_value_equality(
                                            payload_val,
                                            expected_val,
                                            payload_ty,
                                            &format!("enum_payload_eq_{idx}_{slot_idx}"),
                                        )?;
                                        cond = self.builder.build_and(
                                            cond,
                                            payload_eq,
                                            &format!("enum_payload_match_{idx}_{slot_idx}"),
                                        )?;
                                    }
                                }

                                self.builder
                                    .build_conditional_branch(cond, arm_block, next_block)?;

                                self.builder.position_at_end(arm_block);
                                let mut bound_names = Vec::new();
                                for (slot_idx, pattern) in patterns.iter().enumerate() {
                                    if let EnumPattern::Binding(binding_name) = pattern {
                                        let payload_ty = &payload_types[slot_idx];
                                        let payload_val = self.load_enum_slot(
                                            enum_ptr,
                                            slot_idx + 1,
                                            payload_ty,
                                            &format!("enum_bind_{idx}_{slot_idx}"),
                                        )?;
                                        self.declare_local_binding(
                                            function,
                                            binding_name,
                                            payload_val,
                                            payload_ty,
                                        )?;
                                        bound_names.push(binding_name.clone());
                                    }
                                }
                                self.compile_instruction(function, body)?;
                                if self
                                    .builder
                                    .get_insert_block()
                                    .unwrap()
                                    .get_terminator()
                                    .is_none()
                                {
                                    self.builder.build_unconditional_branch(after_block)?;
                                }
                                for name in bound_names {
                                    self.vars.borrow_mut().remove(&name);
                                    self.var_types.borrow_mut().remove(&name);
                                    self.quick_var_types.borrow_mut().remove(&name);
                                }
                            }
                            other => {
                                panic!("Unsupported match on enum type: {other:?}");
                            }
                        },
                        MatchArm::CatchAll(name, runs) => {
                            self.builder.build_unconditional_branch(arm_block)?;
                            self.builder.position_at_end(arm_block);
                            self.declare_local_binding(
                                function,
                                name,
                                scrutinee_value,
                                &scrutinee_type,
                            )?;
                            self.compile_instruction(function, runs)?;
                            if self
                                .builder
                                .get_insert_block()
                                .unwrap()
                                .get_terminator()
                                .is_none()
                            {
                                self.builder.build_unconditional_branch(after_block)?;
                            }
                            self.vars.borrow_mut().remove(name);
                            self.var_types.borrow_mut().remove(name);
                            self.quick_var_types.borrow_mut().remove(name);
                            self.builder.position_at_end(after_block);
                            return Ok(());
                        }
                    }

                    self.builder.position_at_end(next_block);
                    current_block = next_block;
                }

                self.builder.position_at_end(after_block);
                Ok(())
            }
            Instruction::Nothing => Ok(()),
            l => unimplemented!("{:#?}", l),
        }
    }

    fn get_or_create_fopen(&self) -> FunctionValue<'ctx> {
        // fopen signature: (i8*, i8*) -> void*
        self.get_or_add_function("fopen", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            void_ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_fread(&self) -> FunctionValue<'ctx> {
        // fread signature: (i8*, i64, i64, void*) -> i64
        self.get_or_add_function("fread", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            i64_type.fn_type(
                &[
                    i8ptr.into(),
                    i64_type.into(),
                    i64_type.into(),
                    void_ptr.into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_fwrite(&self) -> FunctionValue<'ctx> {
        // fwrite signature: (i8*, i64, i64, void*) -> i64
        self.get_or_add_function("fwrite", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            i64_type.fn_type(
                &[
                    i8ptr.into(),
                    i64_type.into(),
                    i64_type.into(),
                    void_ptr.into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_fclose(&self) -> FunctionValue<'ctx> {
        // fclose signature: (void*) -> i32
        self.get_or_add_function("fclose", || {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            self.context.i32_type().fn_type(&[void_ptr.into()], false)
        })
    }

    fn get_or_create_sprintf(&self) -> FunctionValue<'ctx> {
        // sprintf signature: (i8*, i8*, ...) -> i32
        self.get_or_add_function("sprintf", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            self.context
                .i32_type()
                .fn_type(&[i8ptr.into(), i8ptr.into()], true)
        })
    }

    fn get_or_create_printf(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("printf", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            self.context.i32_type().fn_type(&[i8ptr.into()], true)
        })
    }

    fn get_or_create_free(&self) -> FunctionValue<'ctx> {
        // Correct C signature: void free(void*)
        self.get_or_add_function("free", || {
            let void_ty = self.context.void_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            void_ty.fn_type(&[void_ptr.into()], false)
        })
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
        let sanitize = |name: &str| {
            name.chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>()
        };
        match expr {
            Expr::OptionNone => {
                Ok(self
                    .context
                    .ptr_type(AddressSpace::default())
                    .const_null()
                    .as_basic_value_enum())
            }
            Expr::OptionSome(value) => {
                let compiled = self.compile_expr(value)?;
                match compiled {
                    BasicValueEnum::PointerValue(_) => Ok(compiled),
                    other => panic!("Option::Some expects a pointer-like value, got {other:?}"),
                }
            }
            Expr::ResultOk(value) => {
                let compiled = self.compile_expr(value)?;
                self.lower_result_variant(expr, compiled, true)
            }
            Expr::ResultErr(value) => {
                let compiled = self.compile_expr(value)?;
                self.lower_result_variant(expr, compiled, false)
            }
            Expr::Variable( var_name) => {
                let ptr = *self.vars.borrow().get(var_name).unwrap_or_else(||panic!("{var_name}"));
                let ty = *self.var_types.borrow().get(var_name).unwrap();
                let loaded = self.builder.build_load(ty, ptr, var_name)?;
                 Ok(loaded)
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

            // io.range() - create a fresh RangeBuilder
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(obj, method)
                        if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "range") =>
            {
                let ctor = self.get_or_create_range_builder();
                let builder = self
                    .builder
                    .build_call(ctor, &[], "create_range_builder_call")?
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(builder);
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
            // io.exit(code: Num)
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(obj, method)
                        if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "exit") =>
            {
                let raw_arg = self.compile_expr(&args[0])?;
                let f64_arg = match raw_arg {
                    BasicValueEnum::FloatValue(f) => f,
                    BasicValueEnum::IntValue(i) => self
                        .builder
                        .build_signed_int_to_float(i, self.context.f64_type(), "io_exit_arg")?,
                    other => panic!(
                        "io.exit expects numeric argument, got {other:?}"
                    ),
                };
                let exit_fn = self.get_or_create_io_exit();
                let _ = self
                    .builder
                    .build_call(exit_fn, &[f64_arg.into()], "io_exit_call")?;
                return Ok(self
                    .context
                    .f64_type()
                    .const_float(0.0)
                    .as_basic_value_enum());
            }
            // io.json(payload: Str) -> Maybe(Obj(JsonValue))
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(obj, method)
                        if matches!(&**obj, Expr::Variable(n) if n == "io") && method == "json") =>
            {
                let payload_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                let parse_fn = self.get_or_create_qs_json_parse();
                let result = self
                    .builder
                    .build_call(parse_fn, &[payload_ptr.into()], "io_json_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }

            // num.str()
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(
                        &**callee,
                        Expr::Get(obj, method)
                            if method == "str"
                                && self
                                    .expr_type_matches(obj, |t| matches!(t.unwrap(), Type::Num))
                    ) =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                let compiled_val = self.compile_expr(obj)?;
                let num_val = match compiled_val {
                    BasicValueEnum::FloatValue(f) => f,
                    BasicValueEnum::IntValue(iv) => self.builder.build_signed_int_to_float(
                        iv,
                        self.context.f64_type(),
                        "int_to_float",
                    )?,
                    BasicValueEnum::PointerValue(ptr) => {
                        let loaded = self
                            .builder
                            .build_load(self.context.f64_type(), ptr, "load_num_str")?;
                        if let BasicValueEnum::FloatValue(f) = loaded {
                            f
                        } else if let BasicValueEnum::IntValue(iv) = loaded {
                            self.builder.build_signed_int_to_float(
                                iv,
                                self.context.f64_type(),
                                "ptr_int_to_float",
                            )?
                        } else {
                            panic!(".str() pointer did not contain a numeric value: {loaded:?}")
                        }
                    }
                    other => panic!(".str() called on non-numeric object: {:?}", other),
                };
                let fmt = self
                    .builder
                    .build_global_string_ptr("%f\0", "fmt_str_call")
                    .unwrap();
                let size = self.context.i64_type().const_int(128, false);
                let malloc_fn = self.get_or_create_malloc();
                let buf_ptr = self
                    .builder
                    .build_call(malloc_fn, &[size.into()], "malloc_buf_call")
                    .unwrap();
                let buf_ptr = buf_ptr
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_pointer_value();
                let sprintf_fn = self.get_or_create_sprintf();
                self.builder.build_call(
                    sprintf_fn,
                    &[buf_ptr.into(), fmt.as_pointer_value().into(), num_val.into()],
                    "sprintf_num_str_call",
                )?;
                return Ok(buf_ptr.as_basic_value_enum());
            }

            // json.stringify()
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(_, method) if method == "stringify") =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                if !self.expr_type_matches(obj, |t| matches!(t.unwrap(), Type::JsonValue)) {
                    panic!("json.stringify called on non-Json value");
                }
                let json_ptr = match self.compile_expr(obj)? {
                    BasicValueEnum::PointerValue(p) => p,
                    other => panic!("json.stringify expected pointer handle, got {other:?}"),
                };
                let stringify_fn = self.get_or_create_qs_json_stringify();
                let result = self
                    .builder
                    .build_call(stringify_fn, &[json_ptr.into()], "json_stringify_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // json.str()
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(_, method) if method == "str") =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                if !self.expr_type_matches(obj, |t| matches!(t.unwrap(), Type::JsonValue)) {
                    panic!("json.str called on non-Json value");
                }
                let json_ptr = match self.compile_expr(obj)? {
                    BasicValueEnum::PointerValue(p) => p,
                    other => panic!("json.str expected pointer handle, got {other:?}"),
                };
                let str_fn = self.get_or_create_qs_json_str();
                let result = self
                    .builder
                    .build_call(str_fn, &[json_ptr.into()], "json_str_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // json.len()
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(e, method) if method == "len" && matches!(e.get_type(&self.pctx.borrow()), Ok(Type::JsonValue))) =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                if !self.expr_type_matches(obj, |t| matches!(t.unwrap(), Type::JsonValue)) {
                    panic!("json.len called on non-Json value");
                }
                let json_ptr = match self.compile_expr(obj)? {
                    BasicValueEnum::PointerValue(p) => p,
                    other => panic!("json.len expected pointer handle, got {other:?}"),
                };
                let len_fn = self.get_or_create_qs_json_len();
                let len_call = self
                    .builder
                    .build_call(len_fn, &[json_ptr.into()], "json_len_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap()
                    .into_int_value();
                let len_f64 = self.builder.build_signed_int_to_float(
                    len_call,
                    self.context.f64_type(),
                    "json_len_f64",
                )?;
                return Ok(len_f64.as_basic_value_enum());
            }
            // json.is_null()
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(_, method) if method == "is_null") =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                if !self.expr_type_matches(obj, |t| matches!(t.unwrap(), Type::JsonValue)) {
                    panic!("json.is_null called on non-Json value");
                }
                let json_ptr = match self.compile_expr(obj)? {
                    BasicValueEnum::PointerValue(p) => p,
                    other => panic!("json.is_null expected pointer handle, got {other:?}"),
                };
                let is_null_fn = self.get_or_create_qs_json_is_null();
                let result = self
                    .builder
                    .build_call(is_null_fn, &[json_ptr.into()], "json_is_null_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // json.get(key: Str)
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(e, method) if method == "get" && matches!(e.get_type(&self.pctx.borrow()), Ok(Type::JsonValue))) =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                if !self.expr_type_matches(obj, |t| matches!(t.unwrap(), Type::JsonValue)) {
                    panic!("json.get called on non-Json value");
                }
                let json_ptr = match self.compile_expr(obj)? {
                    BasicValueEnum::PointerValue(p) => p,
                    other => panic!("json.get expected pointer handle, got {other:?}"),
                };
                let key_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                let get_fn = self.get_or_create_qs_json_get();
                let result = self
                    .builder
                    .build_call(get_fn, &[json_ptr.into(), key_ptr.into()], "json_get_call")
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // json.at(index: Num)
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(_, method) if method == "at") =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                if !self.expr_type_matches(obj, |t| matches!(t.unwrap(), Type::JsonValue)) {
                    panic!("json.at called on non-Json value");
                }
                let json_ptr = match self.compile_expr(obj)? {
                    BasicValueEnum::PointerValue(p) => p,
                    other => panic!("json.at expected pointer handle, got {other:?}"),
                };
                let index_val = self.compile_expr(&args[0])?;
                let index_i64 = match index_val {
                    BasicValueEnum::FloatValue(f) => self
                        .builder
                        .build_float_to_signed_int(
                            f,
                            self.context.i64_type(),
                            "json_index_cast",
                        )?,
                    BasicValueEnum::IntValue(i) => {
                        let i64_ty = self.context.i64_type();
                        let width = i.get_type().get_bit_width();
                        if width < 64 {
                            self.builder
                                .build_int_s_extend(i, i64_ty, "json_index_sext")?
                        } else if width > 64 {
                            self.builder
                                .build_int_truncate(i, i64_ty, "json_index_trunc")?
                        } else {
                            i
                        }
                    }
                    other => panic!("json.at index must be numeric, got {other:?}"),
                };
                let index_fn = self.get_or_create_qs_json_index();
                let result = self
                    .builder
                    .build_call(
                        index_fn,
                        &[json_ptr.into(), index_i64.into()],
                        "json_index_call",
                    )
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // Type.from_json(payload: Str)
            Expr::Call(callee, args)
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(_, method) if method == "from_json") =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                let Expr::Variable(type_name) = &**obj else {
                    unreachable!("Guard ensures variable");
                };
                let is_enum = {
                    let binding = self.pctx.borrow();
                    matches!(binding.types.get(type_name), Some(Custype::Enum(_)))
                };
                let canonical_ptr = self
                    .builder
                    .build_global_string_ptr(
                        type_name,
                        &format!("json_type_name_{}_from", sanitize(type_name)),
                    )?
                    .as_pointer_value();
                let payload_ptr = self.compile_expr(&args[0])?.into_pointer_value();
                let from_json_fn = if is_enum {
                    self.get_or_create_qs_enum_from_json()
                } else {
                    self.get_or_create_qs_struct_from_json()
                };
                let result = self
                    .builder
                    .build_call(
                        from_json_fn,
                        &[canonical_ptr.into(), payload_ptr.into()],
                        &format!("{}_from_json_call", sanitize(type_name)),
                    )
                    .unwrap()
                    .try_as_basic_value()
                    .left()
                    .unwrap();
                return Ok(result);
            }
            // object.json()
            Expr::Call(callee, args)
                if args.is_empty()
                    && matches!(&**callee, Expr::Get(obj, method) if method == "json" && matches!(obj.get_type(&self.pctx.borrow()), Ok(Type::Custom(Custype::Object(_))))) =>
            {
                let Expr::Get(obj, _) = &**callee else {
                    unreachable!("Guard ensures Expr::Get");
                };
                let obj_type = self
                    .infer_expr_type(obj)
                    .unwrap_or_else(|e| panic!("Type error in json(): {e}"));
                let type_name = match obj_type {
                    Type::Custom(ref custype) => {
                        let binding = self.pctx.borrow();
                        binding
                            .types
                            .iter()
                            .find(|(_, def)| def == &custype)
                            .map(|(name, _)| name.clone())
                            .unwrap_or_else(|| panic!(
                                "Could not resolve type name for struct when compiling json()"
                            ))
                    }
                    Type::Option(inner) => match *inner {
                        Type::Custom(ref custype) => {
                            let binding = self.pctx.borrow();
                            binding
                                .types
                                .iter()
                                .find(|(_, def)| def == &custype)
                                .map(|(name, _)| name.clone())
                                .unwrap_or_else(|| panic!(
                                    "Could not resolve type name for optional struct when compiling json()"
                                ))
                        }
                        ref other => panic!("json() is not supported on type {other:?}"),
                    },
                    other => panic!("json() is not supported on type {other:?}"),
                };
                let struct_ptr = match self.compile_expr(obj)? {
                    BasicValueEnum::PointerValue(p) => p,
                    other => panic!("json() expected pointer to struct, got {other:?}"),
                };
                let canonical_ptr = self
                    .builder
                    .build_global_string_ptr(
                        &type_name,
                        &format!("json_type_name_{}_to", sanitize(&type_name)),
                    )?
                    .as_pointer_value();
                let to_json_fn = self.get_or_create_qs_struct_to_json();
                let result = self
                    .builder
                    .build_call(
                        to_json_fn,
                        &[canonical_ptr.into(), struct_ptr.into()],
                        &format!("{}_to_json_call", sanitize(&type_name)),
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
                if args.len() == 1
                    && matches!(&**callee, Expr::Get(obj, method)
                        if method == "not_found"
                            && matches!(self.infer_expr_type(obj), Ok(Type::WebReturn))) =>
            {
                if let Expr::Get(obj, _) = &**callee {
                    let response_ptr = match self.compile_expr(obj)? {
                        BasicValueEnum::PointerValue(p) => p,
                        other => panic!("web response not a pointer: {other:?}"),
                    };
                    let fallback_ptr = match self.compile_expr(&args[0])? {
                        BasicValueEnum::PointerValue(p) => p,
                        other => panic!(
                            "Response.not_found expects a string fallback path, got {other:?}"
                        ),
                    };
                    let not_found_fn = self.get_or_create_web_file_not_found();
                    let result = self
                        .builder
                        .build_call(
                            not_found_fn,
                            &[response_ptr.into(), fallback_ptr.into()],
                            "web_not_found_call",
                        )?
                        .try_as_basic_value()
                        .left()
                        .unwrap();
                    return Ok(result);
                }
                unreachable!("guard ensures Expr::Get");
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
                if let Expr::Variable(enum_name) = &**obj_expr {
                    let is_enum = {
                        let binding = self.pctx.borrow();
                        matches!(binding.types.get(enum_name), Some(Custype::Enum(_)))
                    };
                    if is_enum {
                        let enum_value =
                            self.emit_enum_variant(enum_name, prop, &[])?;
                        return Ok(enum_value.as_basic_value_enum());
                    }
                }
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

                if let Expr::Get(enum_expr, variant_name) = &**callee {
                    if let Expr::Variable(enum_name) = &**enum_expr {
                        let is_enum = {
                            let binding = self.pctx.borrow();
                            matches!(binding.types.get(enum_name), Some(Custype::Enum(_)))
                        };
                        if is_enum {
                            let mut compiled_args = Vec::with_capacity(args.len());
                            for arg in args {
                                compiled_args.push(self.compile_expr(arg)?);
                            }
                            let enum_ptr = self.emit_enum_variant(
                                enum_name,
                                variant_name,
                                &compiled_args,
                            )?;
                            return Ok(enum_ptr.as_basic_value_enum());
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

                    Expr::Get(ex, met)
                        if met == "unwrap"
                            && matches!(
                                self.infer_expr_type(ex).unwrap(),
                                (Type::Option(_)) | (Type::Result(_, _))
                            ) =>
                    {
                        let receiver = self.compile_expr(ex)?;
                        let receiver_ptr = match receiver {
                            BasicValueEnum::PointerValue(ptr) => ptr,
                            other => panic!(
                                "unwrap receiver must be pointer-like, got {other:?}"
                            ),
                        };
                        let expr_ty = self
                            .infer_expr_type(ex)
                            .expect("Unable to infer type for unwrap receiver");
                        let unwrap_func = match expr_ty {
                            Type::Option(_) => self.get_or_create_option_unwrap(),
                            Type::Result(_, _) => self.get_or_create_result_unwrap(),
                            _ => unreachable!("guard ensures Option or Result type"),
                        };

                        let call = self
                            .builder
                            .build_call(
                                unwrap_func,
                                &[receiver_ptr.into(), self.compile_expr(&Expr::Literal(Value::Num(self.pctx.borrow().current_line().unwrap_or(67) as f64)))?.into()],
                                "unwrap_call",
                            )?
                            .try_as_basic_value()
                            .left()
                            .unwrap();
                        return Ok(call);
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
                        if method == "join"
                            && matches!(
                                self.infer_expr_type(obj),
                                Ok(Type::List(inner)) if matches!(*inner, Type::Str)
                            ) =>
                    {
                        if args.len() != 1 {
                            panic!(
                                "List::join expects exactly one argument (separator), got {}",
                                args.len()
                            );
                        }

                        let list_val = self.compile_expr(obj)?;
                        let list_ptr = match list_val {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!("List::join called on non-pointer value: {:?}", other),
                        };

                        let sep_val = self.compile_expr(&args[0])?;
                        let sep_ptr = match sep_val {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(
                                "List::join separator must be a string pointer, got {:?}",
                                other
                            ),
                        };

                        let join_fn = self.get_or_create_list_join();
                        let call = self.builder.build_call(
                            join_fn,
                            &[list_ptr.into(), sep_ptr.into()],
                            "list_join_call",
                        )?;

                        let result = call
                            .try_as_basic_value()
                            .left()
                            .unwrap_or_else(|| panic!("List::join call did not yield value"));

                        return Ok(result);
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

                        let mut field_slot_ptr: Option<PointerValue<'ctx>> = None;
                        let mut updated_var: Option<String> = None;

                        // Obtain the underlying buffer pointer, capturing where the list lives so
                        // we can write back a reallocated pointer.
                        let original_buf_ptr = match &**obj {
                            Expr::Get(container, field_name) => {
                                let container_is_object =
                                    match self.infer_expr_type(container) {
                                        Ok(Type::Custom(Custype::Object(_))) => true,
                                        Ok(Type::Option(inner)) => {
                                            matches!(*inner, Type::Custom(Custype::Object(_)))
                                        }
                                        _ => false,
                                    };

                                if container_is_object {
                                    let (slot_ptr, loaded) =
                                        self.load_object_field_slot(container, field_name);
                                    field_slot_ptr = Some(slot_ptr);
                                    match loaded {
                                        BasicValueEnum::PointerValue(p) => p,
                                        other => panic!(
                                            "List field '{field_name}' is not a pointer: {other:?}"
                                        ),
                                    }
                                } else {
                                    match self.compile_expr(obj)? {
                                        BasicValueEnum::PointerValue(p) => p,
                                        _ => panic!("List object not a pointer value"),
                                    }
                                }
                            }
                            Expr::Variable(name) => {
                                updated_var = Some(name.clone());
                                match self.compile_expr(obj)? {
                                    BasicValueEnum::PointerValue(p) => p,
                                    _ => panic!("List object not a pointer value"),
                                }
                            }
                            _ => match self.compile_expr(obj)? {
                                BasicValueEnum::PointerValue(p) => p,
                                _ => panic!("List object not a pointer value"),
                            },
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
                        if let Some(vname) = updated_var {
                            if let Some(var_ptr) = self.vars.borrow().get(&vname) {
                                let _ = self.builder.build_store(*var_ptr, new_raw);
                            }
                        }

                        // Write the pointer back to the owning object field when applicable.
                        if let Some(slot_ptr) = field_slot_ptr {
                            let ptr_ty = self.context.ptr_type(AddressSpace::default());
                            let slot_ptr_cast = self
                                .builder
                                .build_pointer_cast(
                                    slot_ptr,
                                    ptr_ty.ptr_type(AddressSpace::default()),
                                    "list_field_slot",
                                )
                                .unwrap();
                            let _ = self
                                .builder
                                .build_store(slot_ptr_cast, new_raw.as_basic_value_enum());
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
            | Type::Result(_, _)
            | Type::List(_)
            | Type::Io
            | Type::WebReturn
            | Type::RangeBuilder
            | Type::JsonValue
            | Type::Kv(_)
                            | Type::Function(_, _) => match val {
                                BasicValueEnum::PointerValue(p) => p.as_basic_value_enum(),
                                other => panic!(
                                    "Attempted to push non-pointer value into pointer list: {:?}",
                                    other
                                ),
                            },
                            Type::GenericParam(name) => panic!(
                                "List push encountered unresolved generic parameter '{name}'"
                            ),
                            Type::Never => {
                                panic!("Cannot push value of type Never into a list")
                            }
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


                    Expr::Call(callee, args)
                        if args.is_empty()
                            && matches!(
                                &**callee,
                                Expr::Get(obj, method)
                                    if method == "is_some"
                                        && matches!(self.infer_expr_type(obj), Ok(Type::Option(_)))
                            ) =>
                    {
                        let Expr::Get(option_obj, _) = &**callee else {
                            unreachable!("guard ensures Expr::Get");
                        };
                        let option_val = self.compile_expr(option_obj)?;
                        let predicate =
                            self.option_predicate(option_val, true, "option_is_some")?;
                        return Ok(predicate.as_basic_value_enum());
                    }

                    Expr::Call(callee, args)
                        if args.is_empty()
                            && matches!(
                                &**callee,
                                Expr::Get(obj, method)
                                    if method == "is_none"
                                        && matches!(self.infer_expr_type(obj), Ok(Type::Option(_)))
                            ) =>
                    {
                        let Expr::Get(option_obj, _) = &**callee else {
                            unreachable!("guard ensures Expr::Get");
                        };
                        let option_val = self.compile_expr(option_obj)?;
                        let predicate =
                            self.option_predicate(option_val, false, "option_is_none")?;
                        return Ok(predicate.as_basic_value_enum());
                    }

                    Expr::Call(callee, args)
                        if args.len() == 1
                            && matches!(
                                &**callee,
                                Expr::Get(obj, method)
                                    if method == "expect"
                                        && matches!(self.infer_expr_type(obj), Ok(Type::Option(_)))
                            ) =>
                    {
                        let Expr::Get(option_obj, _) = &**callee else {
                            unreachable!("guard ensures Expr::Get");
                        };
                        let message_ptr = match self.compile_expr(&args[0])? {
                            BasicValueEnum::PointerValue(p) => p,
                            other => panic!(
                                "Option::expect message must be a string pointer, got {other:?}"
                            ),
                        };
                        return self.lower_option_force(option_obj, message_ptr, "expect");
                    }



                    Expr::Call(callee, args)
                        if args.is_empty()
                            && matches!(
                                &**callee,
                                Expr::Get(obj, method)
                                    if method == "unwrap_err"
                                        && matches!(self.infer_expr_type(obj), Ok(Type::Result(_, _)))
                            ) =>
                    {
                        let Expr::Get(result_obj, _) = &**callee else {
                            unreachable!("guard ensures Expr::Get");
                        };
                        let message_ptr = self.get_or_create_cstring(
                            "result_unwrap_err_panic_msg",
                            "Result.unwrap_err() tried to access Ok\0",
                        )?;
                        return self.lower_result_force(result_obj, false, message_ptr, "unwrap_err");
                    }

                    Expr::Call(callee, args)
                        if args.is_empty()
                            && matches!(
                                &**callee,
                                Expr::Get(obj, method)
                                    if method == "is_ok"
                                        && matches!(
                                            self.infer_expr_type(obj),
                                            Ok(Type::Result(_, _))
                                        )
                            ) =>
                    {
                        let Expr::Get(result_obj, _) = &**callee else {
                            unreachable!("guard ensures Expr::Get");
                        };
                        let result_val = self.compile_expr(result_obj)?;
                        let (tag, _, _) =
                            self.project_result_slots(result_val, "result_is_ok")?;
                        return Ok(tag.as_basic_value_enum());
                    }

                    Expr::Call(callee, args)
                        if args.is_empty()
                            && matches!(
                                &**callee,
                                Expr::Get(obj, method)
                                    if method == "is_err"
                                        && matches!(
                                            self.infer_expr_type(obj),
                                            Ok(Type::Result(_, _))
                                        )
                            ) =>
                    {
                        let Expr::Get(result_obj, _) = &**callee else {
                            unreachable!("guard ensures Expr::Get");
                        };
                        let result_val = self.compile_expr(result_obj)?;
                        let (tag, _, _) =
                            self.project_result_slots(result_val, "result_is_err")?;
                        let inverted = self
                            .builder
                            .build_not(tag, "result_is_err_value")?;
                        return Ok(inverted.as_basic_value_enum());
                    }

                    Expr::Call(callee, args)
                        if args.len() == 1
                            && matches!(
                                &**callee,
                                Expr::Get(obj, method)
                                    if method == "or_else"
                                        && matches!(self.infer_expr_type(obj), Ok(Type::Option(_)))
                            ) =>
                    {
                        let Expr::Get(option_obj, _) = &**callee else {
                            unreachable!("guard ensures Expr::Get");
                        };
                        let option_val = self.compile_expr(option_obj)?;
                        let fallback_ty = self
                            .infer_expr_type(&args[0])
                            .unwrap_or_else(|e| panic!("Type error: {e}"));
                        let parent_fn = self
                            .builder
                            .get_insert_block()
                            .and_then(|bb| bb.get_parent())
                            .expect("Option::or_else must be inside a function");

                        match option_val {
                            BasicValueEnum::PointerValue(opt_ptr) => {
                                let ptr_ty = opt_ptr.get_type();
                                let result_alloca = self
                                    .builder
                                    .build_alloca(ptr_ty, "or_else_ptr_result")?;
                                let null_ptr = ptr_ty.const_null();
                                let has_value = self.builder.build_int_compare(
                                    IntPredicate::NE,
                                    opt_ptr,
                                    null_ptr,
                                    "or_else_has_value",
                                )?;
                                let then_block =
                                    self.context.append_basic_block(parent_fn, "or_else.some");
                                let else_block =
                                    self.context.append_basic_block(parent_fn, "or_else.none");
                                let cont_block =
                                    self.context.append_basic_block(parent_fn, "or_else.cont");

                                self.builder
                                    .build_conditional_branch(has_value, then_block, else_block)?;

                                self.builder.position_at_end(then_block);
                                self.builder.build_store(result_alloca, opt_ptr)?;
                                if self
                                    .builder
                                    .get_insert_block()
                                    .unwrap()
                                    .get_terminator()
                                    .is_none()
                                {
                                    self.builder.build_unconditional_branch(cont_block)?;
                                }

                                self.builder.position_at_end(else_block);
                                if fallback_ty == Type::Never {
                                    let _ = self.compile_expr(&args[0])?;
                                    if self
                                        .builder
                                        .get_insert_block()
                                        .unwrap()
                                        .get_terminator()
                                        .is_none()
                                    {
                                        self.builder.build_unreachable()?;
                                    }
                                } else {
                                    let fallback_val = self.compile_expr(&args[0])?;
                                    let fallback_ptr = match fallback_val {
                                        BasicValueEnum::PointerValue(p) => p,
                                        other => panic!(
                                            "Option::or_else fallback produced incompatible value: {other:?}"
                                        ),
                                    };
                                    self.builder.build_store(result_alloca, fallback_ptr)?;
                                    self.builder.build_unconditional_branch(cont_block)?;
                                }

                                self.builder.position_at_end(cont_block);
                                let loaded = self
                                    .builder
                                    .build_load(ptr_ty, result_alloca, "or_else_ptr_loaded")?;
                                return Ok(loaded.as_basic_value_enum());
                            }
                            BasicValueEnum::FloatValue(opt_float) => {
                                let float_ty = opt_float.get_type();
                                let result_alloca = self
                                    .builder
                                    .build_alloca(float_ty, "or_else_num_result")?;
                                let zero = float_ty.const_float(0.0);
                                let has_value = self.builder.build_float_compare(
                                    FloatPredicate::ONE,
                                    opt_float,
                                    zero,
                                    "or_else_has_value",
                                )?;
                                let then_block =
                                    self.context.append_basic_block(parent_fn, "or_else.some");
                                let else_block =
                                    self.context.append_basic_block(parent_fn, "or_else.none");
                                let cont_block =
                                    self.context.append_basic_block(parent_fn, "or_else.cont");

                                self.builder
                                    .build_conditional_branch(has_value, then_block, else_block)?;

                                self.builder.position_at_end(then_block);
                                self.builder.build_store(result_alloca, opt_float)?;
                                if self
                                    .builder
                                    .get_insert_block()
                                    .unwrap()
                                    .get_terminator()
                                    .is_none()
                                {
                                    self.builder.build_unconditional_branch(cont_block)?;
                                }

                                self.builder.position_at_end(else_block);
                                if fallback_ty == Type::Never {
                                    let _ = self.compile_expr(&args[0])?;
                                    if self
                                        .builder
                                        .get_insert_block()
                                        .unwrap()
                                        .get_terminator()
                                        .is_none()
                                    {
                                        self.builder.build_unreachable()?;
                                    }
                                } else {
                                    let fallback_val = self.compile_expr(&args[0])?;
                                    let fallback_float = match fallback_val {
                                        BasicValueEnum::FloatValue(f) => f,
                                        BasicValueEnum::IntValue(i) => {
                                            self.builder.build_signed_int_to_float(
                                                i,
                                                float_ty,
                                                "or_else_int_to_float",
                                            )?
                                        }
                                        other => panic!(
                                            "Option::or_else fallback produced incompatible value: {other:?}"
                                        ),
                                    };
                                    self.builder.build_store(result_alloca, fallback_float)?;
                                    self.builder.build_unconditional_branch(cont_block)?;
                                }

                                self.builder.position_at_end(cont_block);
                                let loaded = self
                                    .builder
                                    .build_load(float_ty, result_alloca, "or_else_num_loaded")?;
                                return Ok(loaded);
                            }
                            BasicValueEnum::IntValue(opt_int) => {
                                let int_ty = opt_int.get_type();
                                let result_alloca = self
                                    .builder
                                    .build_alloca(int_ty, "or_else_int_result")?;
                                let zero = int_ty.const_zero();
                                let has_value = self.builder.build_int_compare(
                                    IntPredicate::NE,
                                    opt_int,
                                    zero,
                                    "or_else_has_value",
                                )?;
                                let then_block =
                                    self.context.append_basic_block(parent_fn, "or_else.some");
                                let else_block =
                                    self.context.append_basic_block(parent_fn, "or_else.none");
                                let cont_block =
                                    self.context.append_basic_block(parent_fn, "or_else.cont");

                                self.builder
                                    .build_conditional_branch(has_value, then_block, else_block)?;

                                self.builder.position_at_end(then_block);
                                self.builder.build_store(result_alloca, opt_int)?;
                                if self
                                    .builder
                                    .get_insert_block()
                                    .unwrap()
                                    .get_terminator()
                                    .is_none()
                                {
                                    self.builder.build_unconditional_branch(cont_block)?;
                                }

                                self.builder.position_at_end(else_block);
                                if fallback_ty == Type::Never {
                                    let _ = self.compile_expr(&args[0])?;
                                    if self
                                        .builder
                                        .get_insert_block()
                                        .unwrap()
                                        .get_terminator()
                                        .is_none()
                                    {
                                        self.builder.build_unreachable()?;
                                    }
                                } else {
                                    let fallback_val = self.compile_expr(&args[0])?;
                                    let fallback_int = match fallback_val {
                                        BasicValueEnum::IntValue(i) => i,
                                        other => panic!(
                                            "Option::or_else fallback produced incompatible value: {other:?}"
                                        ),
                                    };
                                    self.builder.build_store(result_alloca, fallback_int)?;
                                    self.builder.build_unconditional_branch(cont_block)?;
                                }

                                self.builder.position_at_end(cont_block);
                                let loaded = self
                                    .builder
                                    .build_load(int_ty, result_alloca, "or_else_int_loaded")?;
                                return Ok(loaded);
                            }
                            other => {
                                panic!(
                                    "Option::or_else not implemented for value representation: {other:?}"
                                )
                            }
                        }
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
        // strcmp signature: (i8*, i8*) -> i32
        self.get_or_add_function("strcmp", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            self.context
                .i32_type()
                .fn_type(&[i8ptr.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_strncmp(&self) -> FunctionValue<'ctx> {
        // strncmp signature: (i8*, i8*, i32) -> i32
        self.get_or_add_function("strncmp", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            self.context.i32_type().fn_type(
                &[i8ptr.into(), i8ptr.into(), self.context.i32_type().into()],
                false,
            )
        })
    }

    fn get_or_create_strlen(&self) -> FunctionValue<'ctx> {
        // strlen signature: (i8*) -> i64
        self.get_or_add_function("strlen", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            self.context.i64_type().fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_atoi(&self) -> FunctionValue<'ctx> {
        // atoi signature: (i8*) -> i64
        self.get_or_add_function("atoi", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            self.context.i64_type().fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_strstr(&self) -> FunctionValue<'ctx> {
        // strstr signature: (i8*, i8*) -> i8*
        self.get_or_add_function("strstr", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_str_replace(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_str_replace", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into(), i8ptr.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_str_split(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_str_split", || {
            let ptr = self.context.ptr_type(AddressSpace::default());
            ptr.fn_type(&[ptr.into(), ptr.into()], false)
        })
    }

    fn get_or_create_list_join(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_list_join", || {
            let ptr = self.context.ptr_type(AddressSpace::default());
            ptr.fn_type(&[ptr.into(), ptr.into()], false)
        })
    }

    fn get_or_create_option_unwrap(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_option_unwrap", || {
            let ptr = self.context.ptr_type(AddressSpace::default());
            ptr.fn_type(&[ptr.into(), self.context.f64_type().into()], false)
        })
    }

    fn get_or_create_result_unwrap(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_result_unwrap", || {
            let ptr = self.context.ptr_type(AddressSpace::default());
            ptr.fn_type(&[ptr.into(), self.context.f64_type().into()], false)
        })
    }

    fn get_or_create_malloc(&self) -> FunctionValue<'ctx> {
        // malloc signature: (i64) -> i8*
        self.get_or_add_function("malloc", || {
            let i64_type = self.context.i64_type();
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i64_type.into()], false)
        })
    }

    fn get_or_create_strcpy(&self) -> FunctionValue<'ctx> {
        // strcpy signature: (i8*, i8*) -> i8*
        self.get_or_add_function("strcpy", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_strcat_c(&self) -> FunctionValue<'ctx> {
        // strcat signature: (i8*, i8*) -> i8*
        self.get_or_add_function("strcat", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_realloc(&self) -> FunctionValue<'ctx> {
        // realloc signature: (i8*, i64) -> i8*
        self.get_or_add_function("realloc", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            i8ptr.fn_type(&[i8ptr.into(), i64_type.into()], false)
        })
    }

    fn get_or_create_memcpy(&self) -> FunctionValue<'ctx> {
        // memcpy signature: (i8*, i8*, i64) -> i8*
        self.get_or_add_function("memcpy", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i64_type = self.context.i64_type();
            i8ptr.fn_type(&[i8ptr.into(), i8ptr.into(), i64_type.into()], false)
        })
    }

    fn get_or_create_fgets(&self) -> FunctionValue<'ctx> {
        // fgets signature: (i8*, i32, void*) -> i8*
        self.get_or_add_function("fgets", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let i32_type = self.context.i32_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into(), i32_type.into(), void_ptr.into()], false)
        })
    }

    fn get_or_create_get_stdin(&self) -> FunctionValue<'ctx> {
        // stdin signature: () -> void*
        self.get_or_add_function("get_stdin", || {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            void_ptr.fn_type(&[], false)
        })
    }

    fn get_or_create_qs_listen_with_callback(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_listen_with_callback", || {
            let i32t = self.context.i32_type();
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            self.context
                .void_type()
                .fn_type(&[i32t.into(), void_ptr.into()], false)
        })
    }

    fn get_or_create_create_request_object(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("create_request_object", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(
                &[
                    i8ptr.into(),
                    i8ptr.into(),
                    i8ptr.into(),
                    i8ptr.into(),
                    i8ptr.into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_get_request_method(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("get_request_method", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_get_request_path(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("get_request_path", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_get_request_body(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("get_request_body", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_get_request_query(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("get_request_query", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_get_request_headers(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("get_request_headers", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_web_helper(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("create_web_helper", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[], false)
        })
    }

    fn get_or_create_range_builder(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("create_range_builder", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[], false)
        })
    }

    fn get_or_create_range_builder_to(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("create_range_builder_to", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(
                &[
                    BasicMetadataTypeEnum::PointerType(
                        self.context.ptr_type(AddressSpace::default()),
                    )
                    .into(),
                    self.context.f64_type().into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_range_builder_from(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("create_range_builder_from", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(
                &[
                    BasicMetadataTypeEnum::PointerType(
                        self.context.ptr_type(AddressSpace::default()),
                    )
                    .into(),
                    self.context.f64_type().into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_range_builder_step(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("create_range_builder_step", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(
                &[
                    BasicMetadataTypeEnum::PointerType(
                        self.context.ptr_type(AddressSpace::default()),
                    )
                    .into(),
                    self.context.f64_type().into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_range_builder_get_from(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("range_builder_get_from", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            self.context.f64_type().fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_range_builder_get_to(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("range_builder_get_to", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            self.context.f64_type().fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_range_builder_get_step(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("range_builder_get_step", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            self.context.f64_type().fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_io_read_file(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("io_read_file", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            void_ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_io_write_file(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("io_write_file", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            void_ptr.fn_type(&[i8ptr.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_qs_panic(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_panic", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            self.context.void_type().fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_io_exit(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("io_exit", || {
            self.context
                .void_type()
                .fn_type(&[self.context.f64_type().into()], false)
        })
    }

    fn get_or_create_web_text(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_text", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_web_json(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_json", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_qs_register_struct_descriptor(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_register_struct_descriptor", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            let ptr_ptr_ty = ptr_ty.ptr_type(AddressSpace::default());
            self.context.void_type().fn_type(
                &[
                    ptr_ty.into(),
                    ptr_ty.into(),
                    self.context.i64_type().into(),
                    ptr_ptr_ty.into(),
                    ptr_ptr_ty.into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_qs_register_enum_variant(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_register_enum_variant", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            let ptr_ptr_ty = ptr_ty.ptr_type(AddressSpace::default());
            self.context.void_type().fn_type(
                &[
                    ptr_ty.into(),
                    ptr_ty.into(),
                    ptr_ty.into(),
                    self.context.i64_type().into(),
                    ptr_ptr_ty.into(),
                ],
                false,
            )
        })
    }

    fn get_or_create_qs_struct_from_json(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_struct_from_json", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into(), ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_enum_from_json(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_enum_from_json", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into(), ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_struct_to_json(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_struct_to_json", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into(), ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_json_parse(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_json_parse", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_json_stringify(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_json_stringify", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_json_is_null(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_json_is_null", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            self.context.bool_type().fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_json_len(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_json_len", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            self.context.i64_type().fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_json_get(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_json_get", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into(), ptr_ty.into()], false)
        })
    }

    fn get_or_create_qs_json_index(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_json_index", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into(), self.context.i64_type().into()], false)
        })
    }

    fn get_or_create_qs_json_str(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_json_str", || {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            ptr_ty.fn_type(&[ptr_ty.into()], false)
        })
    }

    fn get_or_create_web_file(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_file", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_web_file_not_found(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_file_not_found", || {
            let ptr = self.context.ptr_type(AddressSpace::default());
            ptr.fn_type(&[ptr.into(), ptr.into()], false)
        })
    }

    fn get_or_create_web_page(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_page", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i8ptr.into()], false)
        })
    }

    fn get_or_create_web_error_text(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_error_text", || {
            let i32t = self.context.i32_type();
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i32t.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_web_error_page(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_error_page", || {
            let i32t = self.context.i32_type();
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[i32t.into(), i8ptr.into()], false)
        })
    }

    fn get_or_create_web_redirect(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("web_redirect", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let bool_type = self.context.bool_type();
            i8ptr.fn_type(&[i8ptr.into(), bool_type.into()], false)
        })
    }

    fn get_or_create_get_current_method(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("get_current_method", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[], false)
        })
    }

    fn get_or_create_get_current_path(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("get_current_path", || {
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            i8ptr.fn_type(&[], false)
        })
    }

    // ───── Obj (Kv) extern bindings ─────
    fn get_or_create_qs_obj_new(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_obj_new", || {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            void_ptr.fn_type(&[], false)
        })
    }

    fn get_or_create_qs_obj_insert_str(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_obj_insert_str", || {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            self.context
                .void_type()
                .fn_type(&[void_ptr.into(), i8ptr.into(), void_ptr.into()], false)
        })
    }

    fn get_or_create_qs_obj_get_str(&self) -> FunctionValue<'ctx> {
        self.get_or_add_function("qs_obj_get_str", || {
            let void_ptr = self.context.ptr_type(AddressSpace::default());
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            void_ptr.fn_type(&[void_ptr.into(), i8ptr.into()], false)
        })
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
