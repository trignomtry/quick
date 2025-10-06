; ModuleID = 'sum'
source_filename = "sum"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128-Fn32"

@web = global ptr null
@str_literal = private unnamed_addr constant [4 x i8] c"wow\00", align 1
@fmt_s = private unnamed_addr constant [4 x i8] c"%s\0A\00", align 1
@sessions = global ptr null
@str_literal.1 = private unnamed_addr constant [18 x i8] c"This should print\00", align 1
@fmt_s.2 = private unnamed_addr constant [4 x i8] c"%s\0A\00", align 1
@str_literal.3 = private unnamed_addr constant [14 x i8] c"This shouldnt\00", align 1
@fmt_s.4 = private unnamed_addr constant [4 x i8] c"%s\0A\00", align 1

define double @main() {
entry:
  %web_helper_call = call ptr @create_web_helper()
  store ptr %web_helper_call, ptr @web, align 8
  %printf_str = call i32 (ptr, ...) @printf(ptr @fmt_s, ptr @str_literal)
  %obj_new = call ptr @qs_obj_new()
  store ptr %obj_new, ptr @sessions, align 8
  %printf_str1 = call i32 (ptr, ...) @printf(ptr @fmt_s.2, ptr @str_literal.1)
  ret double 0.000000e+00
}

declare ptr @create_web_helper()

declare i32 @printf(ptr, ...)

declare ptr @qs_obj_new()

declare i32 @strcmp(ptr, ptr)

declare i32 @strncmp(ptr, ptr, i32)

declare ptr @malloc(i64)

declare ptr @strcpy(ptr, ptr)

declare ptr @strcat(ptr, ptr)

declare i64 @strlen(ptr)

declare ptr @realloc(ptr, i64)

declare i64 @atoi(ptr)

declare ptr @strstr(ptr, ptr)

declare ptr @qs_str_replace(ptr, ptr, ptr)

declare ptr @qs_str_split(ptr, ptr)

declare i32 @sprintf(ptr, ptr, ...)

declare i32 @rand()

declare ptr @fopen(ptr, ptr)

declare i64 @fread(ptr, i64, i64, ptr)

declare i64 @fwrite(ptr, i64, i64, ptr)

declare i32 @fclose(ptr)

declare ptr @get_stdin()

declare void @qs_listen_with_callback(i32, ptr)

declare ptr @create_request_object(ptr, ptr, ptr, ptr, ptr)

declare ptr @get_request_method(ptr)

declare ptr @get_request_path(ptr)

declare ptr @get_request_body(ptr)

declare ptr @get_request_query(ptr)

declare ptr @get_request_headers(ptr)

declare ptr @create_range_builder()

declare ptr @create_range_builder_to(ptr, double)

declare ptr @create_range_builder_from(ptr, double)

declare ptr @create_range_builder_step(ptr, double)

declare double @range_builder_get_from(ptr)

declare double @range_builder_get_to(ptr)

declare double @range_builder_get_step(ptr)

declare ptr @io_read_file(ptr)

declare double @io_write_file(ptr, ptr)

declare ptr @web_text(ptr)

declare ptr @web_page(ptr)

declare ptr @web_file(ptr)

declare ptr @web_json(ptr)

declare ptr @web_error_text(i32, ptr)

declare ptr @web_error_page(i32, ptr)

declare ptr @web_redirect(ptr, i1)

declare void @qs_obj_insert_str(ptr, ptr, ptr)

declare ptr @qs_obj_get_str(ptr, ptr)
