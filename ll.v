; ModuleID = 'sum'
source_filename = "sum"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128-Fn32"

@web = global ptr null
@inline_env_0_web = internal global ptr null
@str_literal = private unnamed_addr constant [4 x i8] c"/hi\00", align 1
@str_literal.1 = private unnamed_addr constant [7 x i8] c"Hello!\00", align 1
@str_literal.2 = private unnamed_addr constant [10 x i8] c"/api/data\00", align 1
@str_literal.3 = private unnamed_addr constant [22 x i8] c"{\22message\22: \22Hello!\22}\00", align 1
@str_literal.4 = private unnamed_addr constant [10 x i8] c"/redirect\00", align 1
@str_literal.5 = private unnamed_addr constant [4 x i8] c"/hi\00", align 1
@str_literal.6 = private unnamed_addr constant [2 x i8] c"/\00", align 1
@str_literal.7 = private unnamed_addr constant [18 x i8] c"./test/index.html\00", align 1
@str_literal.8 = private unnamed_addr constant [16 x i8] c"./test/404.html\00", align 1

define double @main() {
entry:
  %web_helper_call = call ptr @create_web_helper()
  store ptr %web_helper_call, ptr @web, align 8
  store ptr @web, ptr @inline_env_0_web, align 8
  call void @qs_listen_with_callback(i32 8087, ptr @inline_fn_0)
  ret double 0.000000e+00
}

declare ptr @create_web_helper()

define ptr @inline_fn_0(ptr %0) {
entry:
  %other = alloca ptr, align 8
  %req = alloca ptr, align 8
  store ptr %0, ptr %req, align 8
  %web = alloca ptr, align 8
  %web_env_ptr = load ptr, ptr @inline_env_0_web, align 8
  %web_env_val = load ptr, ptr %web_env_ptr, align 8
  store ptr %web_env_val, ptr %web, align 8
  %req1 = load ptr, ptr %req, align 8
  %get_path_call = call ptr @get_request_path(ptr %req1)
  %strcmp_call = call i32 @strcmp(ptr %get_path_call, ptr @str_literal)
  %streq = icmp eq i32 %strcmp_call, 0
  br i1 %streq, label %then, label %else

common.ret:                                       ; preds = %else18, %then17, %then10, %then2, %then
  %common.ret.op = phi ptr [ %web_call, %then ], [ %web_call9, %then2 ], [ %web_redirect_call, %then10 ], [ %web_call24, %then17 ], [ %web_call27, %else18 ]
  ret ptr %common.ret.op

then:                                             ; preds = %entry
  %web_call = call ptr @web_text(ptr @str_literal.1)
  br label %common.ret

else:                                             ; preds = %entry
  %req5 = load ptr, ptr %req, align 8
  %get_path_call6 = call ptr @get_request_path(ptr %req5)
  %strcmp_call7 = call i32 @strcmp(ptr %get_path_call6, ptr @str_literal.2)
  %streq8 = icmp eq i32 %strcmp_call7, 0
  br i1 %streq8, label %then2, label %else3

then2:                                            ; preds = %else
  %web_call9 = call ptr @web_json(ptr @str_literal.3)
  br label %common.ret

else3:                                            ; preds = %else
  %req13 = load ptr, ptr %req, align 8
  %get_path_call14 = call ptr @get_request_path(ptr %req13)
  %strcmp_call15 = call i32 @strcmp(ptr %get_path_call14, ptr @str_literal.4)
  %streq16 = icmp eq i32 %strcmp_call15, 0
  br i1 %streq16, label %then10, label %else11

then10:                                           ; preds = %else3
  %web_redirect_call = call ptr @web_redirect(ptr @str_literal.5, i1 false)
  br label %common.ret

else11:                                           ; preds = %else3
  %req20 = load ptr, ptr %req, align 8
  %get_path_call21 = call ptr @get_request_path(ptr %req20)
  %strcmp_call22 = call i32 @strcmp(ptr %get_path_call21, ptr @str_literal.6)
  %streq23 = icmp eq i32 %strcmp_call22, 0
  br i1 %streq23, label %then17, label %else18

then17:                                           ; preds = %else11
  %web_call24 = call ptr @web_file(ptr @str_literal.7)
  br label %common.ret

else18:                                           ; preds = %else11
  %req25 = load ptr, ptr %req, align 8
  %get_path_call26 = call ptr @get_request_path(ptr %req25)
  store ptr %get_path_call26, ptr %other, align 8
  %web_call27 = call ptr @web_file(ptr @str_literal.8)
  br label %common.ret
}

declare ptr @get_request_path(ptr)

declare i32 @strcmp(ptr, ptr)

declare ptr @web_text(ptr)

declare ptr @web_json(ptr)

declare ptr @web_redirect(ptr, i1)

declare ptr @web_file(ptr)

declare void @qs_listen_with_callback(i32, ptr)

declare i32 @strncmp(ptr, ptr, i32)

declare i32 @printf(ptr, ...)

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

declare ptr @create_request_object(ptr, ptr, ptr, ptr, ptr)

declare ptr @get_request_method(ptr)

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

declare ptr @web_page(ptr)

declare ptr @web_error_text(i32, ptr)

declare ptr @web_error_page(i32, ptr)

declare ptr @qs_obj_new()

declare void @qs_obj_insert_str(ptr, ptr, ptr)

declare ptr @qs_obj_get_str(ptr, ptr)
