; ModuleID = 'sum'
source_filename = "sum"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"

@__qs_arena = local_unnamed_addr global ptr null
@json_type_name_Request = private unnamed_addr constant [8 x i8] c"Request\00", align 1
@json_type_sig_Request = private unnamed_addr constant [67 x i8] c"Object{body:Option(Str),headers:Str,method:Str,path:Str,query:Str}\00", align 1
@json_field_name_Request_0 = private unnamed_addr constant [6 x i8] c"query\00", align 1
@json_field_name_Request_1 = private unnamed_addr constant [8 x i8] c"headers\00", align 1
@json_field_name_Request_2 = private unnamed_addr constant [7 x i8] c"method\00", align 1
@json_field_name_Request_3 = private unnamed_addr constant [5 x i8] c"path\00", align 1
@json_field_type_Request_3 = private unnamed_addr constant [4 x i8] c"Str\00", align 1
@json_field_name_Request_4 = private unnamed_addr constant [5 x i8] c"body\00", align 1
@json_field_type_Request_4 = private unnamed_addr constant [12 x i8] c"Option(Str)\00", align 1
@str_literal = private unnamed_addr constant [14 x i8] c"Hello, World!\00", align 1
@web = local_unnamed_addr global ptr null
@str_literal.1 = private unnamed_addr constant [9 x i8] c"./lander\00", align 1

define noundef double @main() local_unnamed_addr {
entry:
  %arena_create = tail call ptr @arena_create(i64 67108864)
  store ptr %arena_create, ptr @__qs_arena, align 8
  %json_field_names9 = alloca [5 x ptr], align 8
  %json_field_types10 = alloca [5 x ptr], align 8
  store ptr @json_field_name_Request_0, ptr %json_field_names9, align 8
  %json_name_slot1 = getelementptr inbounds ptr, ptr %json_field_names9, i64 1
  store ptr @json_field_name_Request_1, ptr %json_name_slot1, align 8
  %json_name_slot2 = getelementptr inbounds ptr, ptr %json_field_names9, i64 2
  store ptr @json_field_name_Request_2, ptr %json_name_slot2, align 8
  %json_name_slot3 = getelementptr inbounds ptr, ptr %json_field_names9, i64 3
  store ptr @json_field_name_Request_3, ptr %json_name_slot3, align 8
  %json_name_slot4 = getelementptr inbounds ptr, ptr %json_field_names9, i64 4
  store ptr @json_field_name_Request_4, ptr %json_name_slot4, align 8
  store ptr @json_field_type_Request_3, ptr %json_field_types10, align 8
  %json_type_slot5 = getelementptr inbounds ptr, ptr %json_field_types10, i64 1
  store ptr @json_field_type_Request_3, ptr %json_type_slot5, align 8
  %json_type_slot6 = getelementptr inbounds ptr, ptr %json_field_types10, i64 2
  store ptr @json_field_type_Request_3, ptr %json_type_slot6, align 8
  %json_type_slot7 = getelementptr inbounds ptr, ptr %json_field_types10, i64 3
  store ptr @json_field_type_Request_3, ptr %json_type_slot7, align 8
  %json_type_slot8 = getelementptr inbounds ptr, ptr %json_field_types10, i64 4
  store ptr @json_field_type_Request_4, ptr %json_type_slot8, align 8
  call void @qs_register_struct_descriptor(ptr nonnull @json_type_name_Request, ptr nonnull @json_type_sig_Request, i64 5, ptr nonnull %json_field_names9, ptr nonnull %json_field_types10)
  %puts = call i32 @puts(ptr nonnull dereferenceable(1) @str_literal)
  %web_helper_call = call ptr @create_web_helper()
  store ptr %web_helper_call, ptr @web, align 8
  call void @qs_listen_with_callback(i64 8080, ptr nonnull @inline_fn_0)
  ret double 0.000000e+00
}

declare ptr @arena_create(i64) local_unnamed_addr

declare void @qs_register_struct_descriptor(ptr, ptr, i64, ptr, ptr) local_unnamed_addr

declare ptr @create_web_helper() local_unnamed_addr

define ptr @inline_fn_0(ptr %0) {
entry:
  %arena_ptr = load ptr, ptr @__qs_arena, align 8
  %inline_fn_0_mark = tail call i64 @arena_mark(ptr %arena_ptr)
  %arena_ptr1 = load ptr, ptr @__qs_arena, align 8
  %block_arena_mark = tail call i64 @arena_mark(ptr %arena_ptr1)
  %get_path_call = tail call ptr @get_request_path(ptr %0)
  %len2 = tail call i64 @strlen(ptr noundef nonnull dereferenceable(1) %get_path_call)
  %total_len = add i64 %len2, 9
  %arena_ptr3 = load ptr, ptr @__qs_arena, align 8
  %malloc_buf = tail call ptr @arena_alloc(ptr %arena_ptr3, i64 %total_len, i64 1)
  tail call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(9) %malloc_buf, ptr noundef nonnull align 1 dereferenceable(9) @str_literal.1, i64 9, i1 false)
  %strcat_call = tail call ptr @strcat(ptr noundef nonnull dereferenceable(1) %malloc_buf, ptr noundef nonnull dereferenceable(1) %get_path_call)
  %web_call = tail call ptr @web_file(ptr %malloc_buf)
  %arena_ptr4 = load ptr, ptr @__qs_arena, align 8
  tail call void @arena_release(ptr %arena_ptr4, i64 %inline_fn_0_mark)
  ret ptr %web_call
}

declare i64 @arena_mark(ptr) local_unnamed_addr

declare ptr @get_request_path(ptr) local_unnamed_addr

; Function Attrs: mustprogress nofree nounwind willreturn memory(argmem: read)
declare i64 @strlen(ptr nocapture) local_unnamed_addr #0

; Function Attrs: mustprogress nofree nounwind willreturn memory(argmem: readwrite)
declare ptr @strcat(ptr noalias returned, ptr noalias nocapture readonly) local_unnamed_addr #1

declare ptr @arena_alloc(ptr, i64, i64) local_unnamed_addr

declare ptr @web_file(ptr) local_unnamed_addr

declare void @arena_release(ptr, i64) local_unnamed_addr

declare void @qs_listen_with_callback(i64, ptr) local_unnamed_addr

; Function Attrs: nofree nounwind
declare noundef i32 @puts(ptr nocapture noundef readonly) local_unnamed_addr #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #3

declare i32 @strcmp(ptr, ptr)

declare i32 @printf(ptr, ...)

declare ptr @strcpy(ptr, ptr)

declare ptr @memcpy(ptr, ptr, i64)

declare i64 @atoi(ptr)

declare ptr @strstr(ptr, ptr)

declare ptr @qs_option_unwrap(ptr, double)

declare ptr @qs_result_unwrap(ptr, double)

declare ptr @qs_str_replace(ptr, ptr, ptr)

declare ptr @qs_str_split(ptr, ptr)

declare ptr @qs_list_join(ptr, ptr)

declare i32 @sprintf(ptr, ptr, ...)

declare i32 @rand()

declare void @qs_panic(ptr)

declare void @io_exit(double)

declare ptr @fopen(ptr, ptr)

declare i64 @fread(ptr, i64, i64, ptr)

declare i64 @fwrite(ptr, i64, i64, ptr)

declare i32 @fclose(ptr)

declare ptr @get_stdin()

declare ptr @io_read_file(ptr)

declare ptr @io_write_file(ptr, ptr)

declare ptr @create_request_object(ptr, ptr, ptr, ptr, ptr)

declare ptr @get_request_method(ptr)

declare ptr @get_request_body(ptr)

declare ptr @get_request_query(ptr)

declare ptr @get_request_headers(ptr)

declare ptr @web_page(ptr)

declare ptr @web_file_not_found(ptr, ptr)

declare ptr @web_json(ptr)

declare ptr @web_error_text(i64, ptr)

declare ptr @web_error_page(i64, ptr)

declare ptr @web_redirect(ptr, i1)

declare ptr @web_text(ptr)

declare ptr @create_range_builder()

declare ptr @range_builder_to(ptr, i64)

declare ptr @range_builder_from(ptr, i64)

declare ptr @range_builder_step(ptr, i64)

declare i64 @range_builder_get_from(ptr)

declare i64 @range_builder_get_to(ptr)

declare i64 @range_builder_get_step(ptr)

declare ptr @qs_obj_new()

declare void @qs_obj_insert_str(ptr, ptr, ptr)

declare ptr @qs_obj_get_str(ptr, ptr)

declare void @qs_register_enum_variant(ptr, ptr, ptr, i64, ptr)

declare ptr @qs_struct_from_json(ptr, ptr)

declare ptr @qs_enum_from_json(ptr, ptr)

declare ptr @qs_struct_to_json(ptr, ptr)

declare ptr @qs_json_parse(ptr)

declare ptr @qs_json_stringify(ptr)

declare i1 @qs_json_is_null(ptr)

declare i64 @qs_json_len(ptr)

declare ptr @qs_json_get(ptr, ptr)

declare ptr @qs_json_index(ptr, i64)

declare ptr @qs_json_str(ptr)

declare void @arena_free(ptr, ptr)

declare void @arena_pin(ptr, ptr)

declare void @arena_retain(ptr, ptr)

declare void @arena_release_ref(ptr, ptr)

declare void @arena_destroy(ptr)

attributes #0 = { mustprogress nofree nounwind willreturn memory(argmem: read) }
attributes #1 = { mustprogress nofree nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { nofree nounwind }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
