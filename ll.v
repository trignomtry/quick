; ModuleID = 'sum'
source_filename = "sum"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"

@__qs_arena = local_unnamed_addr global ptr null
@json_type_name_Request = private unnamed_addr constant [8 x i8] c"Request\00", align 1
@json_type_sig_Request = private unnamed_addr constant [67 x i8] c"Object{body:Option(Str),headers:Str,method:Str,path:Str,query:Str}\00", align 1
@json_field_name_Request_0 = private unnamed_addr constant [7 x i8] c"method\00", align 1
@json_field_name_Request_1 = private unnamed_addr constant [5 x i8] c"path\00", align 1
@json_field_name_Request_2 = private unnamed_addr constant [8 x i8] c"headers\00", align 1
@json_field_name_Request_3 = private unnamed_addr constant [5 x i8] c"body\00", align 1
@json_field_type_Request_3 = private unnamed_addr constant [12 x i8] c"Option(Str)\00", align 1
@json_field_name_Request_4 = private unnamed_addr constant [6 x i8] c"query\00", align 1
@json_field_type_Request_4 = private unnamed_addr constant [4 x i8] c"Str\00", align 1
@total = local_unnamed_addr global i64 0
@start = local_unnamed_addr global i64 0
@end = local_unnamed_addr global i64 0
@str_literal = private unnamed_addr constant [25 x i8] c"QuickScript Loop Total: \00", align 1
@fmt_str_call_int = private unnamed_addr constant [4 x i8] c"%ld\00", align 1

define noundef double @main() local_unnamed_addr {
entry:
  %arena_create = tail call ptr @arena_create(i64 67108864)
  store ptr %arena_create, ptr @__qs_arena, align 8
  %json_field_names17 = alloca [5 x ptr], align 8
  %json_field_types18 = alloca [5 x ptr], align 8
  store ptr @json_field_name_Request_0, ptr %json_field_names17, align 8
  %json_name_slot1 = getelementptr inbounds ptr, ptr %json_field_names17, i64 1
  store ptr @json_field_name_Request_1, ptr %json_name_slot1, align 8
  %json_name_slot2 = getelementptr inbounds ptr, ptr %json_field_names17, i64 2
  store ptr @json_field_name_Request_2, ptr %json_name_slot2, align 8
  %json_name_slot3 = getelementptr inbounds ptr, ptr %json_field_names17, i64 3
  store ptr @json_field_name_Request_3, ptr %json_name_slot3, align 8
  %json_name_slot4 = getelementptr inbounds ptr, ptr %json_field_names17, i64 4
  store ptr @json_field_name_Request_4, ptr %json_name_slot4, align 8
  store ptr @json_field_type_Request_4, ptr %json_field_types18, align 8
  %json_type_slot5 = getelementptr inbounds ptr, ptr %json_field_types18, i64 1
  store ptr @json_field_type_Request_4, ptr %json_type_slot5, align 8
  %json_type_slot6 = getelementptr inbounds ptr, ptr %json_field_types18, i64 2
  store ptr @json_field_type_Request_4, ptr %json_type_slot6, align 8
  %json_type_slot7 = getelementptr inbounds ptr, ptr %json_field_types18, i64 3
  store ptr @json_field_type_Request_3, ptr %json_type_slot7, align 8
  %json_type_slot8 = getelementptr inbounds ptr, ptr %json_field_types18, i64 4
  store ptr @json_field_type_Request_4, ptr %json_type_slot8, align 8
  call void @qs_register_struct_descriptor(ptr nonnull @json_type_name_Request, ptr nonnull @json_type_sig_Request, i64 5, ptr nonnull %json_field_names17, ptr nonnull %json_field_types18)
  store i64 0, ptr @total, align 8
  store i64 0, ptr @start, align 8
  store i64 10000000, ptr @end, align 8
  %create_range_builder_call = call ptr @create_range_builder()
  %start = load i64, ptr @start, align 8
  %range_builder_set = call ptr @range_builder_from(ptr %create_range_builder_call, i64 %start)
  %end = load i64, ptr @end, align 8
  %range_builder_set9 = call ptr @range_builder_to(ptr %range_builder_set, i64 %end)
  %range_from = call i64 @range_builder_get_from(ptr %range_builder_set9)
  %range_to = call i64 @range_builder_get_to(ptr %range_builder_set9)
  %range_step = call i64 @range_builder_get_step(ptr %range_builder_set9)
  %step_pos = icmp sgt i64 %range_step, 0
  %step_neg = icmp slt i64 %range_step, 0
  %for_lt19 = icmp slt i64 %range_from, %range_to
  %for_gt20 = icmp sgt i64 %range_from, %range_to
  %cond_neg_or_zero21 = select i1 %step_neg, i1 %for_gt20, i1 false
  %for_cond_sel22 = select i1 %step_pos, i1 %for_lt19, i1 %cond_neg_or_zero21
  br i1 %for_cond_sel22, label %for.body.preheader, label %for.cont

for.body.preheader:                               ; preds = %entry
  br label %for.body

for.body:                                         ; preds = %for.body.preheader, %for.body
  %i.023 = phi i64 [ %for_iter_next, %for.body ], [ %range_from, %for.body.preheader ]
  %0 = icmp slt i64 %range_step, 0
  %1 = icmp sgt i64 %range_step, 0
  %arena_ptr = load ptr, ptr @__qs_arena, align 8
  %for_body_mark = call i64 @arena_mark(ptr %arena_ptr)
  %arena_ptr10 = load ptr, ptr @__qs_arena, align 8
  %block_arena_mark = call i64 @arena_mark(ptr %arena_ptr10)
  %total = load i64, ptr @total, align 8
  %2 = add i64 %i.023, %total
  store i64 %2, ptr @total, align 8
  call void @arena_release(ptr %arena_ptr10, i64 %block_arena_mark)
  call void @arena_release(ptr %arena_ptr, i64 %for_body_mark)
  %for_iter_next = add i64 %i.023, %range_step
  %3 = add i64 %range_step, %i.023
  %for_lt = icmp slt i64 %3, %range_to
  %for_gt = icmp sgt i64 %3, %range_to
  %cond_neg_or_zero = select i1 %0, i1 %for_gt, i1 false
  %for_cond_sel = select i1 %1, i1 %for_lt, i1 %cond_neg_or_zero
  br i1 %for_cond_sel, label %for.body, label %for.cont

for.cont:                                         ; preds = %for.body, %entry
  %total12 = load i64, ptr @total, align 8
  %arena_ptr13 = load ptr, ptr @__qs_arena, align 8
  %malloc_buf_call = call ptr @arena_alloc(ptr %arena_ptr13, i64 128, i64 1)
  %sprintf_num_str_call_int = call i32 (ptr, ptr, ...) @sprintf(ptr nonnull dereferenceable(1) %malloc_buf_call, ptr nonnull dereferenceable(1) @fmt_str_call_int, i64 %total12)
  %len2 = call i64 @strlen(ptr noundef nonnull dereferenceable(1) %malloc_buf_call)
  %total_len = add i64 %len2, 25
  %arena_ptr14 = load ptr, ptr @__qs_arena, align 8
  %malloc_buf = call ptr @arena_alloc(ptr %arena_ptr14, i64 %total_len, i64 1)
  call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(25) %malloc_buf, ptr noundef nonnull align 1 dereferenceable(25) @str_literal, i64 25, i1 false)
  %strcat_call = call ptr @strcat(ptr noundef nonnull dereferenceable(1) %malloc_buf, ptr noundef nonnull dereferenceable(1) %malloc_buf_call)
  %puts = call i32 @puts(ptr nonnull dereferenceable(1) %malloc_buf)
  ret double 0.000000e+00
}

declare ptr @arena_create(i64) local_unnamed_addr

declare void @qs_register_struct_descriptor(ptr, ptr, i64, ptr, ptr) local_unnamed_addr

declare ptr @create_range_builder() local_unnamed_addr

declare ptr @range_builder_from(ptr, i64) local_unnamed_addr

declare ptr @range_builder_to(ptr, i64) local_unnamed_addr

declare i64 @range_builder_get_from(ptr) local_unnamed_addr

declare i64 @range_builder_get_to(ptr) local_unnamed_addr

declare i64 @range_builder_get_step(ptr) local_unnamed_addr

declare i64 @arena_mark(ptr) local_unnamed_addr

declare void @arena_release(ptr, i64) local_unnamed_addr

declare ptr @arena_alloc(ptr, i64, i64) local_unnamed_addr

; Function Attrs: nofree nounwind
declare noundef i32 @sprintf(ptr noalias nocapture noundef writeonly, ptr nocapture noundef readonly, ...) local_unnamed_addr #0

; Function Attrs: mustprogress nofree nounwind willreturn memory(argmem: read)
declare i64 @strlen(ptr nocapture) local_unnamed_addr #1

; Function Attrs: mustprogress nofree nounwind willreturn memory(argmem: readwrite)
declare ptr @strcat(ptr noalias returned, ptr noalias nocapture readonly) local_unnamed_addr #2

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #3

; Function Attrs: nofree nounwind
declare noundef i32 @puts(ptr nocapture noundef readonly) local_unnamed_addr #0

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

declare void @qs_listen_with_callback(i32, ptr)

declare ptr @create_request_object(ptr, ptr, ptr, ptr, ptr)

declare ptr @get_request_method(ptr)

declare ptr @get_request_path(ptr)

declare ptr @get_request_body(ptr)

declare ptr @get_request_query(ptr)

declare ptr @get_request_headers(ptr)

declare ptr @create_web_helper()

declare ptr @web_page(ptr)

declare ptr @web_file(ptr)

declare ptr @web_file_not_found(ptr, ptr)

declare ptr @web_json(ptr)

declare ptr @web_error_text(i32, ptr)

declare ptr @web_error_page(i32, ptr)

declare ptr @web_redirect(ptr, i1)

declare ptr @web_text(ptr)

declare ptr @range_builder_step(ptr, i64)

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

attributes #0 = { nofree nounwind }
attributes #1 = { mustprogress nofree nounwind willreturn memory(argmem: read) }
attributes #2 = { mustprogress nofree nounwind willreturn memory(argmem: readwrite) }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
