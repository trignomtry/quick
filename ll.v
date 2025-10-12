; ModuleID = 'sum'
source_filename = "sum"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128-Fn32"

@str_literal = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@str_literal.1 = private unnamed_addr constant [2 x i8] c"\\\00", align 1
@str_literal.2 = private unnamed_addr constant [2 x i8] c"\22\00", align 1
@str_literal.3 = private unnamed_addr constant [7 x i8] c"string\00", align 1
@str_literal.4 = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@str_literal.5 = private unnamed_addr constant [2 x i8] c"\22\00", align 1
@str_literal.6 = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@str_literal.7 = private unnamed_addr constant [5 x i8] c" \0A\0D\09\00", align 1
@str_literal.8 = private unnamed_addr constant [7 x i8] c"{}[],:\00", align 1
@str_literal.9 = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@str_literal.10 = private unnamed_addr constant [12 x i8] c"{}[],:\22 \0A\0D\09\00", align 1
@str_literal.11 = private unnamed_addr constant [8 x i8] c"literal\00", align 1
@str_literal.12 = private unnamed_addr constant [28 x i8] c"tokenizer returned 0 tokens\00", align 1
@fmt_s = private unnamed_addr constant [4 x i8] c"%s\0A\00", align 1
@nil_literal = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.13 = private unnamed_addr constant [2 x i8] c"{\00", align 1
@str_literal.14 = private unnamed_addr constant [17 x i8] c"expected {, saw \00", align 1
@fmt_s.15 = private unnamed_addr constant [4 x i8] c"%s\0A\00", align 1
@nil_literal.16 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.17 = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@str_literal.18 = private unnamed_addr constant [2 x i8] c"}\00", align 1
@str_literal.19 = private unnamed_addr constant [7 x i8] c"string\00", align 1
@nil_literal.20 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.21 = private unnamed_addr constant [2 x i8] c":\00", align 1
@nil_literal.22 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.23 = private unnamed_addr constant [5 x i8] c"name\00", align 1
@str_literal.24 = private unnamed_addr constant [7 x i8] c"string\00", align 1
@nil_literal.25 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.26 = private unnamed_addr constant [6 x i8] c"tasks\00", align 1
@str_literal.27 = private unnamed_addr constant [2 x i8] c"[\00", align 1
@nil_literal.28 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.29 = private unnamed_addr constant [2 x i8] c"]\00", align 1
@str_literal.30 = private unnamed_addr constant [2 x i8] c"{\00", align 1
@nil_literal.31 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.32 = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@str_literal.33 = private unnamed_addr constant [2 x i8] c"}\00", align 1
@str_literal.34 = private unnamed_addr constant [7 x i8] c"string\00", align 1
@nil_literal.35 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.36 = private unnamed_addr constant [2 x i8] c":\00", align 1
@nil_literal.37 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.38 = private unnamed_addr constant [5 x i8] c"text\00", align 1
@str_literal.39 = private unnamed_addr constant [7 x i8] c"string\00", align 1
@nil_literal.40 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.41 = private unnamed_addr constant [10 x i8] c"completed\00", align 1
@nil_literal.42 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.43 = private unnamed_addr constant [8 x i8] c"literal\00", align 1
@str_literal.44 = private unnamed_addr constant [7 x i8] c"string\00", align 1
@str_literal.45 = private unnamed_addr constant [5 x i8] c"true\00", align 1
@str_literal.46 = private unnamed_addr constant [6 x i8] c"false\00", align 1
@nil_literal.47 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@nil_literal.48 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@nil_literal.49 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.50 = private unnamed_addr constant [2 x i8] c",\00", align 1
@str_literal.51 = private unnamed_addr constant [2 x i8] c"}\00", align 1
@nil_literal.52 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@nil_literal.53 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.54 = private unnamed_addr constant [2 x i8] c",\00", align 1
@str_literal.55 = private unnamed_addr constant [2 x i8] c"]\00", align 1
@nil_literal.56 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@nil_literal.57 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.58 = private unnamed_addr constant [7 x i8] c"string\00", align 1
@str_literal.59 = private unnamed_addr constant [8 x i8] c"literal\00", align 1
@nil_literal.60 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@str_literal.61 = private unnamed_addr constant [2 x i8] c",\00", align 1
@str_literal.62 = private unnamed_addr constant [2 x i8] c"}\00", align 1
@nil_literal.63 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@nil_literal.64 = private unnamed_addr constant [4 x i8] c"nil\00", align 1
@web = global ptr null
@str_literal.65 = private unnamed_addr constant [5 x i8] c"json\00", align 1
@sessions = global ptr null
@str_literal.66 = private unnamed_addr constant [30 x i8] c"{\22name\22: \22Trig\22, \22tasks\22: []}\00", align 1
@maybe_user = global ptr null
@str_literal.67 = private unnamed_addr constant [14 x i8] c"/api/register\00", align 1
@fmt_str = private unnamed_addr constant [3 x i8] c"%f\00", align 1
@str_literal.68 = private unnamed_addr constant [10 x i8] c"Success: \00", align 1
@str_literal.69 = private unnamed_addr constant [5 x i8] c"Bruh\00", align 1
@str_literal.70 = private unnamed_addr constant [2 x i8] c"/\00", align 1
@str_literal.71 = private unnamed_addr constant [2 x i8] c"/\00", align 1
@str_literal.72 = private unnamed_addr constant [11 x i8] c"index.html\00", align 1
@str_literal.73 = private unnamed_addr constant [7 x i8] c"./test\00", align 1
@str_literal.74 = private unnamed_addr constant [6 x i8] c"guest\00", align 1
@str_literal.75 = private unnamed_addr constant [6 x i8] c"Guest\00", align 1
@str_literal.76 = private unnamed_addr constant [6 x i8] c"found\00", align 1
@fmt_s.77 = private unnamed_addr constant [4 x i8] c"%s\0A\00", align 1
@str_literal.78 = private unnamed_addr constant [7 x i8] c"{name}\00", align 1
@str_literal.79 = private unnamed_addr constant [8 x i8] c"{tasks}\00", align 1
@str_literal.80 = private unnamed_addr constant [3 x i8] c"[]\00", align 1
@str_literal.81 = private unnamed_addr constant [10 x i8] c"Not found\00", align 1
@_MergedGlobals = private global <{ ptr, ptr, ptr }> zeroinitializer, align 8

@inline_env_0_web = internal alias ptr, ptr @_MergedGlobals
@inline_env_0_sessions = internal alias ptr, getelementptr inbounds (<{ ptr, ptr, ptr }>, ptr @_MergedGlobals, i32 0, i32 1)
@inline_env_0_maybe_user = internal alias ptr, getelementptr inbounds (<{ ptr, ptr, ptr }>, ptr @_MergedGlobals, i32 0, i32 2)

define double @main() {
entry:
  %web_helper_call = call ptr @create_web_helper()
  store ptr %web_helper_call, ptr @web, align 8
  %obj_new = call ptr @qs_obj_new()
  store ptr %obj_new, ptr @sessions, align 8
  %call_json__parse_user_json = call ptr @json__parse_user_json(ptr @str_literal.66)
  store ptr %call_json__parse_user_json, ptr @maybe_user, align 8
  store ptr @web, ptr @_MergedGlobals, align 8
  store ptr @sessions, ptr getelementptr inbounds (<{ ptr, ptr, ptr }>, ptr @_MergedGlobals, i32 0, i32 1), align 8
  store ptr @maybe_user, ptr getelementptr inbounds (<{ ptr, ptr, ptr }>, ptr @_MergedGlobals, i32 0, i32 2), align 8
  call void @qs_listen_with_callback(i32 8087, ptr @inline_fn_0)
  ret double 0.000000e+00
}

define ptr @json__json_tokenize(ptr %0) {
entry:
  %c = alloca ptr, align 8
  %literal = alloca ptr, align 8
  %ch = alloca ptr, align 8
  %current = alloca ptr, align 8
  %escaping = alloca i1, align 1
  %in_string = alloca i1, align 1
  %i = alloca double, align 8
  %length = alloca i64, align 8
  %tokens = alloca ptr, align 8
  %raw = alloca ptr, align 8
  store ptr %0, ptr %raw, align 8
  %malloc = call ptr @malloc(i64 8)
  %len_ptr142 = bitcast ptr %malloc to ptr
  store double 0.000000e+00, ptr %len_ptr142, align 8
  store ptr %malloc, ptr %tokens, align 8
  %raw1 = load ptr, ptr %raw, align 8
  %strlen_call = call i64 @strlen(ptr %raw1)
  store i64 %strlen_call, ptr %length, align 8
  store double 0.000000e+00, ptr %i, align 8
  store i1 false, ptr %in_string, align 1
  store i1 false, ptr %escaping, align 1
  store ptr @str_literal, ptr %current, align 8
  br label %while.cond

while.cond:                                       ; preds = %then110, %then130, %then52, %then46, %then38, %cont9, %entry
  %i2 = load double, ptr %i, align 8
  %length3 = load i64, ptr %length, align 8
  %number_value = sitofp i64 %length3 to double
  %lttmp = fcmp olt double %i2, %number_value
  %andtmp = select i1 %lttmp, i1 true, i1 false
  br i1 %andtmp, label %while.body, label %while.cont

while.body:                                       ; preds = %while.cond
  %raw4 = load ptr, ptr %raw, align 8
  %i5 = load double, ptr %i, align 8
  %number = fptosi double %i5 to i64
  %char_ptr = getelementptr inbounds i8, ptr %raw4, i64 %number
  %load_char = load i8, ptr %char_ptr, align 1
  %malloc_char = call ptr @malloc(i64 2)
  %buf_0143 = bitcast ptr %malloc_char to ptr
  %buf_1 = getelementptr inbounds i8, ptr %malloc_char, i64 1
  store i8 %load_char, ptr %buf_0143, align 1
  store i8 0, ptr %buf_1, align 1
  store ptr %malloc_char, ptr %ch, align 8
  %in_string6 = load i1, ptr %in_string, align 1
  br i1 %in_string6, label %then, label %else

while.cont:                                       ; preds = %while.cond
  %in_string138 = load i1, ptr %in_string, align 1
  br i1 %in_string138, label %then135, label %cont137

then:                                             ; preds = %while.body
  %escaping10 = load i1, ptr %escaping, align 1
  br i1 %escaping10, label %then7, label %else8

else:                                             ; preds = %while.body
  %ch41 = load ptr, ptr %ch, align 8
  %strcmp_call42 = call i32 @strcmp(ptr %ch41, ptr @str_literal.5)
  %streq43 = icmp eq i32 %strcmp_call42, 0
  br i1 %streq43, label %then38, label %else39

then7:                                            ; preds = %then
  %current11 = load ptr, ptr %current, align 8
  %ch12 = load ptr, ptr %ch, align 8
  %len1 = call i64 @strlen(ptr %current11)
  %len2 = call i64 @strlen(ptr %ch12)
  %len_sum = add i64 %len1, %len2
  %total_len = add i64 %len_sum, 1
  %malloc_buf = call ptr @malloc(i64 %total_len)
  %strcpy_call = call ptr @strcpy(ptr %malloc_buf, ptr %current11)
  %strcat_call = call ptr @strcat(ptr %malloc_buf, ptr %ch12)
  store ptr %malloc_buf, ptr %current, align 8
  store i1 false, ptr %escaping, align 1
  br label %cont9

else8:                                            ; preds = %then
  %ch16 = load ptr, ptr %ch, align 8
  %strcmp_call = call i32 @strcmp(ptr %ch16, ptr @str_literal.1)
  %streq = icmp eq i32 %strcmp_call, 0
  br i1 %streq, label %then13, label %else14

cont9:                                            ; preds = %then17, %then25, %then13, %then7
  %i37 = load double, ptr %i, align 8
  %addtmp = fadd double %i37, 1.000000e+00
  store double %addtmp, ptr %i, align 8
  br label %while.cond

then13:                                           ; preds = %else8
  store i1 true, ptr %escaping, align 1
  br label %cont9

else14:                                           ; preds = %else8
  %ch20 = load ptr, ptr %ch, align 8
  %strcmp_call21 = call i32 @strcmp(ptr %ch20, ptr @str_literal.2)
  %streq22 = icmp eq i32 %strcmp_call21, 0
  br i1 %streq22, label %then17, label %then25

then17:                                           ; preds = %else14
  %tokens23 = load ptr, ptr %tokens, align 8
  %len_load = load double, ptr %tokens23, align 8
  %len_to_i64 = fptosi double %len_load to i64
  %needed_slots = add i64 %len_to_i64, 2
  %push_bytes = mul i64 8, %needed_slots
  %realloc_list_push = call ptr @realloc(ptr %tokens23, i64 %push_bytes)
  store ptr %realloc_list_push, ptr %tokens, align 8
  %push_idx = add i64 %len_to_i64, 1
  %push_elem_ptr = getelementptr inbounds double, ptr %realloc_list_push, i64 %push_idx
  %malloc_obj = call ptr @malloc(i64 16)
  %current24 = load ptr, ptr %current, align 8
  %field_value144 = bitcast ptr %malloc_obj to ptr
  store ptr %current24, ptr %field_value144, align 8
  %field_kind = getelementptr inbounds i64, ptr %malloc_obj, i64 1
  store ptr @str_literal.3, ptr %field_kind, align 8
  store ptr %malloc_obj, ptr %push_elem_ptr, align 8
  %len_inc = add i64 %len_to_i64, 1
  %len_to_f64 = sitofp i64 %len_inc to double
  store double %len_to_f64, ptr %realloc_list_push, align 8
  store ptr @str_literal.4, ptr %current, align 8
  store i1 false, ptr %in_string, align 1
  br label %cont9

then25:                                           ; preds = %else14
  %current28 = load ptr, ptr %current, align 8
  %ch29 = load ptr, ptr %ch, align 8
  %len130 = call i64 @strlen(ptr %current28)
  %len231 = call i64 @strlen(ptr %ch29)
  %len_sum32 = add i64 %len130, %len231
  %total_len33 = add i64 %len_sum32, 1
  %malloc_buf34 = call ptr @malloc(i64 %total_len33)
  %strcpy_call35 = call ptr @strcpy(ptr %malloc_buf34, ptr %current28)
  %strcat_call36 = call ptr @strcat(ptr %malloc_buf34, ptr %ch29)
  store ptr %malloc_buf34, ptr %current, align 8
  br label %cont9

then38:                                           ; preds = %else
  store i1 true, ptr %in_string, align 1
  store ptr @str_literal.6, ptr %current, align 8
  %i44 = load double, ptr %i, align 8
  %addtmp45 = fadd double %i44, 1.000000e+00
  store double %addtmp45, ptr %i, align 8
  br label %while.cond

else39:                                           ; preds = %else
  %ch49 = load ptr, ptr %ch, align 8
  %strstr_call = call ptr @strstr(ptr @str_literal.7, ptr %ch49)
  %neq_nil = icmp ne ptr %strstr_call, null
  br i1 %neq_nil, label %then46, label %else47

then46:                                           ; preds = %else39
  %i50 = load double, ptr %i, align 8
  %addtmp51 = fadd double %i50, 1.000000e+00
  store double %addtmp51, ptr %i, align 8
  br label %while.cond

else47:                                           ; preds = %else39
  %ch55 = load ptr, ptr %ch, align 8
  %strstr_call56 = call ptr @strstr(ptr @str_literal.8, ptr %ch55)
  %neq_nil57 = icmp ne ptr %strstr_call56, null
  br i1 %neq_nil57, label %then52, label %then75

then52:                                           ; preds = %else47
  %tokens58 = load ptr, ptr %tokens, align 8
  %len_load59 = load double, ptr %tokens58, align 8
  %len_to_i6460 = fptosi double %len_load59 to i64
  %needed_slots61 = add i64 %len_to_i6460, 2
  %push_bytes62 = mul i64 8, %needed_slots61
  %realloc_list_push63 = call ptr @realloc(ptr %tokens58, i64 %push_bytes62)
  store ptr %realloc_list_push63, ptr %tokens, align 8
  %push_idx64 = add i64 %len_to_i6460, 1
  %push_elem_ptr65 = getelementptr inbounds double, ptr %realloc_list_push63, i64 %push_idx64
  %malloc_obj66 = call ptr @malloc(i64 16)
  %ch67 = load ptr, ptr %ch, align 8
  %field_value68145 = bitcast ptr %malloc_obj66 to ptr
  store ptr %ch67, ptr %field_value68145, align 8
  %ch69 = load ptr, ptr %ch, align 8
  %field_kind70 = getelementptr inbounds i64, ptr %malloc_obj66, i64 1
  store ptr %ch69, ptr %field_kind70, align 8
  store ptr %malloc_obj66, ptr %push_elem_ptr65, align 8
  %len_inc71 = add i64 %len_to_i6460, 1
  %len_to_f6472 = sitofp i64 %len_inc71 to double
  store double %len_to_f6472, ptr %realloc_list_push63, align 8
  %i73 = load double, ptr %i, align 8
  %addtmp74 = fadd double %i73, 1.000000e+00
  store double %addtmp74, ptr %i, align 8
  br label %while.cond

then75:                                           ; preds = %else47
  store ptr @str_literal.9, ptr %literal, align 8
  br label %while.cond78

while.cond78:                                     ; preds = %cont95, %then75
  %i81 = load double, ptr %i, align 8
  %length82 = load i64, ptr %length, align 8
  %number_value83 = sitofp i64 %length82 to double
  %lttmp84 = fcmp olt double %i81, %number_value83
  br i1 %lttmp84, label %while.body79, label %while.cont80

while.body79:                                     ; preds = %while.cond78
  %raw85 = load ptr, ptr %raw, align 8
  %i86 = load double, ptr %i, align 8
  %number87 = fptosi double %i86 to i64
  %char_ptr88 = getelementptr inbounds i8, ptr %raw85, i64 %number87
  %load_char89 = load i8, ptr %char_ptr88, align 1
  %malloc_char90 = call ptr @malloc(i64 2)
  %buf_091146 = bitcast ptr %malloc_char90 to ptr
  %buf_192 = getelementptr inbounds i8, ptr %malloc_char90, i64 1
  store i8 %load_char89, ptr %buf_091146, align 1
  store i8 0, ptr %buf_192, align 1
  store ptr %malloc_char90, ptr %c, align 8
  %c96 = load ptr, ptr %c, align 8
  %strstr_call97 = call ptr @strstr(ptr @str_literal.10, ptr %c96)
  %neq_nil98 = icmp ne ptr %strstr_call97, null
  br i1 %neq_nil98, label %while.cont80, label %cont95

while.cont80:                                     ; preds = %while.body79, %while.cond78
  %literal113 = load ptr, ptr %literal, align 8
  %strlen_call114 = call i64 @strlen(ptr %literal113)
  %number_value115 = sitofp i64 %strlen_call114 to double
  %gttmp = fcmp ogt double %number_value115, 0.000000e+00
  br i1 %gttmp, label %then110, label %then130

cont95:                                           ; preds = %while.body79
  %literal99 = load ptr, ptr %literal, align 8
  %c100 = load ptr, ptr %c, align 8
  %len1101 = call i64 @strlen(ptr %literal99)
  %len2102 = call i64 @strlen(ptr %c100)
  %len_sum103 = add i64 %len1101, %len2102
  %total_len104 = add i64 %len_sum103, 1
  %malloc_buf105 = call ptr @malloc(i64 %total_len104)
  %strcpy_call106 = call ptr @strcpy(ptr %malloc_buf105, ptr %literal99)
  %strcat_call107 = call ptr @strcat(ptr %malloc_buf105, ptr %c100)
  store ptr %malloc_buf105, ptr %literal, align 8
  %i108 = load double, ptr %i, align 8
  %addtmp109 = fadd double %i108, 1.000000e+00
  store double %addtmp109, ptr %i, align 8
  br label %while.cond78

then110:                                          ; preds = %while.cont80
  %tokens116 = load ptr, ptr %tokens, align 8
  %len_load117 = load double, ptr %tokens116, align 8
  %len_to_i64118 = fptosi double %len_load117 to i64
  %needed_slots119 = add i64 %len_to_i64118, 2
  %push_bytes120 = mul i64 8, %needed_slots119
  %realloc_list_push121 = call ptr @realloc(ptr %tokens116, i64 %push_bytes120)
  store ptr %realloc_list_push121, ptr %tokens, align 8
  %push_idx122 = add i64 %len_to_i64118, 1
  %push_elem_ptr123 = getelementptr inbounds double, ptr %realloc_list_push121, i64 %push_idx122
  %malloc_obj124 = call ptr @malloc(i64 16)
  %literal125 = load ptr, ptr %literal, align 8
  %field_value126147 = bitcast ptr %malloc_obj124 to ptr
  store ptr %literal125, ptr %field_value126147, align 8
  %field_kind127 = getelementptr inbounds i64, ptr %malloc_obj124, i64 1
  store ptr @str_literal.11, ptr %field_kind127, align 8
  store ptr %malloc_obj124, ptr %push_elem_ptr123, align 8
  %len_inc128 = add i64 %len_to_i64118, 1
  %len_to_f64129 = sitofp i64 %len_inc128 to double
  store double %len_to_f64129, ptr %realloc_list_push121, align 8
  br label %while.cond

then130:                                          ; preds = %while.cont80
  %i133 = load double, ptr %i, align 8
  %addtmp134 = fadd double %i133, 1.000000e+00
  store double %addtmp134, ptr %i, align 8
  br label %while.cond

common.ret:                                       ; preds = %cont137, %then135
  %common.ret.op = phi ptr [ %malloc139, %then135 ], [ %tokens141, %cont137 ]
  ret ptr %common.ret.op

then135:                                          ; preds = %while.cont
  %malloc139 = call ptr @malloc(i64 8)
  %len_ptr140148 = bitcast ptr %malloc139 to ptr
  store double 0.000000e+00, ptr %len_ptr140148, align 8
  br label %common.ret

cont137:                                          ; preds = %while.cont
  %tokens141 = load ptr, ptr %tokens, align 8
  br label %common.ret
}

define ptr @json__parse_user_json(ptr %0) {
entry:
  %bool_token = alloca ptr, align 8
  %task_key = alloca ptr, align 8
  %seen_completed = alloca i1, align 1
  %seen_text = alloca i1, align 1
  %task_completed = alloca i1, align 1
  %task_text = alloca ptr, align 8
  %parsed_tasks = alloca ptr, align 8
  %key = alloca ptr, align 8
  %has_tasks = alloca i1, align 1
  %tasks = alloca ptr, align 8
  %has_name = alloca i1, align 1
  %name = alloca ptr, align 8
  %current = alloca double, align 8
  %total = alloca double, align 8
  %tokens = alloca ptr, align 8
  %raw = alloca ptr, align 8
  store ptr %0, ptr %raw, align 8
  %raw1 = load ptr, ptr %raw, align 8
  %call_json__json_tokenize = call ptr @json__json_tokenize(ptr %raw1)
  store ptr %call_json__json_tokenize, ptr %tokens, align 8
  %tokens2 = load ptr, ptr %tokens, align 8
  %len = load double, ptr %tokens2, align 8
  %eqtmp = fcmp oeq double %len, 0.000000e+00
  br i1 %eqtmp, label %then, label %cont

common.ret:                                       ; preds = %while.cont130, %then99, %then64, %cont29, %logic_rhs438, %then416, %logic_rhs400, %logic_rhs111, %logic_rhs76, %logic_rhs, %cont19, %while.cont165, %cont347, %logic_rhs351, %cont136, %then227, %cont185, %else228, %logic_rhs288, %else297, %then262, %logic_rhs239, %logic_rhs212, %cont171, %while.cont, %logic_rhs483, %cont503, %then3, %then
  %common.ret.op = phi ptr [ null, %then ], [ null, %then3 ], [ %malloc_obj506, %cont503 ], [ null, %logic_rhs483 ], [ null, %while.cont ], [ null, %cont171 ], [ null, %logic_rhs212 ], [ null, %logic_rhs239 ], [ null, %then262 ], [ null, %else297 ], [ null, %logic_rhs288 ], [ null, %else228 ], [ null, %cont185 ], [ null, %then227 ], [ null, %cont136 ], [ null, %logic_rhs351 ], [ null, %cont347 ], [ null, %while.cont165 ], [ null, %cont19 ], [ null, %logic_rhs ], [ null, %logic_rhs76 ], [ null, %logic_rhs111 ], [ null, %logic_rhs400 ], [ null, %then416 ], [ null, %logic_rhs438 ], [ null, %cont29 ], [ null, %then64 ], [ null, %then99 ], [ null, %while.cont130 ]
  ret ptr %common.ret.op

then:                                             ; preds = %entry
  %printf_str = call i32 (ptr, ...) @printf(ptr @fmt_s, ptr @str_literal.12)
  br label %common.ret

cont:                                             ; preds = %entry
  %tokens6 = load ptr, ptr %tokens, align 8
  %list_index = getelementptr inbounds double, ptr %tokens6, i64 1
  %load_ptr_elem = load ptr, ptr %list_index, align 8
  %load_kind = getelementptr inbounds i64, ptr %load_ptr_elem, i64 1
  %kind = load ptr, ptr %load_kind, align 8
  %strcmp_call = call i32 @strcmp(ptr %kind, ptr @str_literal.13)
  %strneq = icmp ne i32 %strcmp_call, 0
  %tokens7 = load ptr, ptr %tokens, align 8
  br i1 %strneq, label %then3, label %cont5

then3:                                            ; preds = %cont
  %list_index8 = getelementptr inbounds double, ptr %tokens7, i64 1
  %load_ptr_elem9 = load ptr, ptr %list_index8, align 8
  %load_kind10 = getelementptr inbounds i64, ptr %load_ptr_elem9, i64 1
  %kind11 = load ptr, ptr %load_kind10, align 8
  %len1 = call i64 @strlen(ptr @str_literal.14)
  %len2 = call i64 @strlen(ptr %kind11)
  %len_sum = add i64 %len1, %len2
  %total_len = add i64 %len_sum, 1
  %malloc_buf = call ptr @malloc(i64 %total_len)
  %strcpy_call = call ptr @strcpy(ptr %malloc_buf, ptr @str_literal.14)
  %strcat_call = call ptr @strcat(ptr %malloc_buf, ptr %kind11)
  %printf_str12 = call i32 (ptr, ...) @printf(ptr @fmt_s.15, ptr %malloc_buf)
  br label %common.ret

cont5:                                            ; preds = %cont
  %len14 = load double, ptr %tokens7, align 8
  store double %len14, ptr %total, align 8
  store double 1.000000e+00, ptr %current, align 8
  store ptr @str_literal.17, ptr %name, align 8
  store i1 false, ptr %has_name, align 1
  %malloc = call ptr @malloc(i64 8)
  %len_ptr518 = bitcast ptr %malloc to ptr
  store double 0.000000e+00, ptr %len_ptr518, align 8
  store ptr %malloc, ptr %tasks, align 8
  store i1 false, ptr %has_tasks, align 1
  br label %while.cond

while.cond:                                       ; preds = %cont66, %then456, %logic_rhs462, %cont5
  %current15 = load double, ptr %current, align 8
  %total16 = load double, ptr %total, align 8
  %lttmp = fcmp olt double %current15, %total16
  br i1 %lttmp, label %while.body, label %while.cont

while.body:                                       ; preds = %while.cond
  %tokens20 = load ptr, ptr %tokens, align 8
  %current21 = load double, ptr %current, align 8
  %number = fptosi double %current21 to i64
  %idx_plus1 = add i64 %number, 1
  %list_index22 = getelementptr inbounds double, ptr %tokens20, i64 %idx_plus1
  %load_ptr_elem23 = load ptr, ptr %list_index22, align 8
  %load_kind24 = getelementptr inbounds i64, ptr %load_ptr_elem23, i64 1
  %kind25 = load ptr, ptr %load_kind24, align 8
  %strcmp_call26 = call i32 @strcmp(ptr %kind25, ptr @str_literal.18)
  %streq = icmp eq i32 %strcmp_call26, 0
  br i1 %streq, label %while.cont, label %cont19

while.cont:                                       ; preds = %while.body, %while.cond
  %current480 = load double, ptr %current, align 8
  %total481 = load double, ptr %total, align 8
  %getmp482 = fcmp oge double %current480, %total481
  br i1 %getmp482, label %common.ret, label %logic_rhs483

cont19:                                           ; preds = %while.body
  %tokens30 = load ptr, ptr %tokens, align 8
  %current31 = load double, ptr %current, align 8
  %number32 = fptosi double %current31 to i64
  %idx_plus133 = add i64 %number32, 1
  %list_index34 = getelementptr inbounds double, ptr %tokens30, i64 %idx_plus133
  %load_ptr_elem35 = load ptr, ptr %list_index34, align 8
  %load_kind36 = getelementptr inbounds i64, ptr %load_ptr_elem35, i64 1
  %kind37 = load ptr, ptr %load_kind36, align 8
  %strcmp_call38 = call i32 @strcmp(ptr %kind37, ptr @str_literal.19)
  %strneq39 = icmp ne i32 %strcmp_call38, 0
  br i1 %strneq39, label %common.ret, label %cont29

cont29:                                           ; preds = %cont19
  %tokens40 = load ptr, ptr %tokens, align 8
  %current41 = load double, ptr %current, align 8
  %number42 = fptosi double %current41 to i64
  %idx_plus143 = add i64 %number42, 1
  %list_index44 = getelementptr inbounds double, ptr %tokens40, i64 %idx_plus143
  %load_ptr_elem45 = load ptr, ptr %list_index44, align 8
  %load_value519 = bitcast ptr %load_ptr_elem45 to ptr
  %value = load ptr, ptr %load_value519, align 8
  store ptr %value, ptr %key, align 8
  %current46 = load double, ptr %current, align 8
  %addtmp = fadd double %current46, 1.000000e+00
  store double %addtmp, ptr %current, align 8
  %current50 = load double, ptr %current, align 8
  %total51 = load double, ptr %total, align 8
  %getmp = fcmp oge double %current50, %total51
  br i1 %getmp, label %common.ret, label %logic_rhs

cont49:                                           ; preds = %logic_rhs
  %current62 = load double, ptr %current, align 8
  %addtmp63 = fadd double %current62, 1.000000e+00
  store double %addtmp63, ptr %current, align 8
  %key67 = load ptr, ptr %key, align 8
  %strcmp_call68 = call i32 @strcmp(ptr %key67, ptr @str_literal.23)
  %streq69 = icmp eq i32 %strcmp_call68, 0
  br i1 %streq69, label %then64, label %else65

logic_rhs:                                        ; preds = %cont29
  %tokens52 = load ptr, ptr %tokens, align 8
  %current53 = load double, ptr %current, align 8
  %number54 = fptosi double %current53 to i64
  %idx_plus155 = add i64 %number54, 1
  %list_index56 = getelementptr inbounds double, ptr %tokens52, i64 %idx_plus155
  %load_ptr_elem57 = load ptr, ptr %list_index56, align 8
  %load_kind58 = getelementptr inbounds i64, ptr %load_ptr_elem57, i64 1
  %kind59 = load ptr, ptr %load_kind58, align 8
  %strcmp_call60 = call i32 @strcmp(ptr %kind59, ptr @str_literal.21)
  %strneq61 = icmp ne i32 %strcmp_call60, 0
  br i1 %strneq61, label %common.ret, label %cont49

then64:                                           ; preds = %cont49
  %current73 = load double, ptr %current, align 8
  %total74 = load double, ptr %total, align 8
  %getmp75 = fcmp oge double %current73, %total74
  br i1 %getmp75, label %common.ret, label %logic_rhs76

else65:                                           ; preds = %cont49
  %key102 = load ptr, ptr %key, align 8
  %strcmp_call103 = call i32 @strcmp(ptr %key102, ptr @str_literal.26)
  %streq104 = icmp eq i32 %strcmp_call103, 0
  %current108 = load double, ptr %current, align 8
  %total109 = load double, ptr %total, align 8
  br i1 %streq104, label %then99, label %then416

cont66:                                           ; preds = %cont396, %then425, %cont72
  %current459 = load double, ptr %current, align 8
  %total460 = load double, ptr %total, align 8
  %lttmp461 = fcmp olt double %current459, %total460
  br i1 %lttmp461, label %logic_rhs462, label %while.cond

cont72:                                           ; preds = %logic_rhs76
  %tokens89 = load ptr, ptr %tokens, align 8
  %current90 = load double, ptr %current, align 8
  %number91 = fptosi double %current90 to i64
  %idx_plus192 = add i64 %number91, 1
  %list_index93 = getelementptr inbounds double, ptr %tokens89, i64 %idx_plus192
  %load_ptr_elem94 = load ptr, ptr %list_index93, align 8
  %load_value95520 = bitcast ptr %load_ptr_elem94 to ptr
  %value96 = load ptr, ptr %load_value95520, align 8
  store ptr %value96, ptr %name, align 8
  store i1 true, ptr %has_name, align 1
  %current97 = load double, ptr %current, align 8
  %addtmp98 = fadd double %current97, 1.000000e+00
  store double %addtmp98, ptr %current, align 8
  br label %cont66

logic_rhs76:                                      ; preds = %then64
  %tokens78 = load ptr, ptr %tokens, align 8
  %current79 = load double, ptr %current, align 8
  %number80 = fptosi double %current79 to i64
  %idx_plus181 = add i64 %number80, 1
  %list_index82 = getelementptr inbounds double, ptr %tokens78, i64 %idx_plus181
  %load_ptr_elem83 = load ptr, ptr %list_index82, align 8
  %load_kind84 = getelementptr inbounds i64, ptr %load_ptr_elem83, i64 1
  %kind85 = load ptr, ptr %load_kind84, align 8
  %strcmp_call86 = call i32 @strcmp(ptr %kind85, ptr @str_literal.24)
  %strneq87 = icmp ne i32 %strcmp_call86, 0
  br i1 %strneq87, label %common.ret, label %cont72

then99:                                           ; preds = %else65
  %1 = fcmp oge double %current108, %total109
  br i1 %1, label %common.ret, label %logic_rhs111

cont107:                                          ; preds = %logic_rhs111
  %current124 = load double, ptr %current, align 8
  %addtmp125 = fadd double %current124, 1.000000e+00
  store double %addtmp125, ptr %current, align 8
  %malloc126 = call ptr @malloc(i64 8)
  %len_ptr127521 = bitcast ptr %malloc126 to ptr
  store double 0.000000e+00, ptr %len_ptr127521, align 8
  store ptr %malloc126, ptr %parsed_tasks, align 8
  br label %while.cond128

logic_rhs111:                                     ; preds = %then99
  %tokens113 = load ptr, ptr %tokens, align 8
  %current114 = load double, ptr %current, align 8
  %number115 = fptosi double %current114 to i64
  %idx_plus1116 = add i64 %number115, 1
  %list_index117 = getelementptr inbounds double, ptr %tokens113, i64 %idx_plus1116
  %load_ptr_elem118 = load ptr, ptr %list_index117, align 8
  %load_kind119 = getelementptr inbounds i64, ptr %load_ptr_elem118, i64 1
  %kind120 = load ptr, ptr %load_kind119, align 8
  %strcmp_call121 = call i32 @strcmp(ptr %kind120, ptr @str_literal.27)
  %strneq122 = icmp ne i32 %strcmp_call121, 0
  br i1 %strneq122, label %common.ret, label %cont107

while.cond128:                                    ; preds = %cont368, %then373, %logic_rhs379, %cont107
  %current131 = load double, ptr %current, align 8
  %total132 = load double, ptr %total, align 8
  %lttmp133 = fcmp olt double %current131, %total132
  br i1 %lttmp133, label %while.body129, label %while.cont130

while.body129:                                    ; preds = %while.cond128
  %tokens137 = load ptr, ptr %tokens, align 8
  %current138 = load double, ptr %current, align 8
  %number139 = fptosi double %current138 to i64
  %idx_plus1140 = add i64 %number139, 1
  %list_index141 = getelementptr inbounds double, ptr %tokens137, i64 %idx_plus1140
  %load_ptr_elem142 = load ptr, ptr %list_index141, align 8
  %load_kind143 = getelementptr inbounds i64, ptr %load_ptr_elem142, i64 1
  %kind144 = load ptr, ptr %load_kind143, align 8
  %strcmp_call145 = call i32 @strcmp(ptr %kind144, ptr @str_literal.29)
  %streq146 = icmp eq i32 %strcmp_call145, 0
  br i1 %streq146, label %while.cont130, label %cont136

while.cont130:                                    ; preds = %while.body129, %while.cond128
  %current397 = load double, ptr %current, align 8
  %total398 = load double, ptr %total, align 8
  %getmp399 = fcmp oge double %current397, %total398
  br i1 %getmp399, label %common.ret, label %logic_rhs400

cont136:                                          ; preds = %while.body129
  %tokens151 = load ptr, ptr %tokens, align 8
  %current152 = load double, ptr %current, align 8
  %number153 = fptosi double %current152 to i64
  %idx_plus1154 = add i64 %number153, 1
  %list_index155 = getelementptr inbounds double, ptr %tokens151, i64 %idx_plus1154
  %load_ptr_elem156 = load ptr, ptr %list_index155, align 8
  %load_kind157 = getelementptr inbounds i64, ptr %load_ptr_elem156, i64 1
  %kind158 = load ptr, ptr %load_kind157, align 8
  %strcmp_call159 = call i32 @strcmp(ptr %kind158, ptr @str_literal.30)
  %strneq160 = icmp ne i32 %strcmp_call159, 0
  br i1 %strneq160, label %common.ret, label %cont150

cont150:                                          ; preds = %cont136
  %current161 = load double, ptr %current, align 8
  %addtmp162 = fadd double %current161, 1.000000e+00
  store double %addtmp162, ptr %current, align 8
  store ptr @str_literal.32, ptr %task_text, align 8
  store i1 false, ptr %task_completed, align 1
  store i1 false, ptr %seen_text, align 1
  store i1 false, ptr %seen_completed, align 1
  br label %while.cond163

while.cond163:                                    ; preds = %cont229, %then325, %logic_rhs331, %cont150
  %current166 = load double, ptr %current, align 8
  %total167 = load double, ptr %total, align 8
  %lttmp168 = fcmp olt double %current166, %total167
  br i1 %lttmp168, label %while.body164, label %while.cont165

while.body164:                                    ; preds = %while.cond163
  %tokens172 = load ptr, ptr %tokens, align 8
  %current173 = load double, ptr %current, align 8
  %number174 = fptosi double %current173 to i64
  %idx_plus1175 = add i64 %number174, 1
  %list_index176 = getelementptr inbounds double, ptr %tokens172, i64 %idx_plus1175
  %load_ptr_elem177 = load ptr, ptr %list_index176, align 8
  %load_kind178 = getelementptr inbounds i64, ptr %load_ptr_elem177, i64 1
  %kind179 = load ptr, ptr %load_kind178, align 8
  %strcmp_call180 = call i32 @strcmp(ptr %kind179, ptr @str_literal.33)
  %streq181 = icmp eq i32 %strcmp_call180, 0
  br i1 %streq181, label %while.cont165, label %cont171

while.cont165:                                    ; preds = %while.body164, %while.cond163
  %current348 = load double, ptr %current, align 8
  %total349 = load double, ptr %total, align 8
  %getmp350 = fcmp oge double %current348, %total349
  br i1 %getmp350, label %common.ret, label %logic_rhs351

cont171:                                          ; preds = %while.body164
  %tokens186 = load ptr, ptr %tokens, align 8
  %current187 = load double, ptr %current, align 8
  %number188 = fptosi double %current187 to i64
  %idx_plus1189 = add i64 %number188, 1
  %list_index190 = getelementptr inbounds double, ptr %tokens186, i64 %idx_plus1189
  %load_ptr_elem191 = load ptr, ptr %list_index190, align 8
  %load_kind192 = getelementptr inbounds i64, ptr %load_ptr_elem191, i64 1
  %kind193 = load ptr, ptr %load_kind192, align 8
  %strcmp_call194 = call i32 @strcmp(ptr %kind193, ptr @str_literal.34)
  %strneq195 = icmp ne i32 %strcmp_call194, 0
  br i1 %strneq195, label %common.ret, label %cont185

cont185:                                          ; preds = %cont171
  %tokens196 = load ptr, ptr %tokens, align 8
  %current197 = load double, ptr %current, align 8
  %number198 = fptosi double %current197 to i64
  %idx_plus1199 = add i64 %number198, 1
  %list_index200 = getelementptr inbounds double, ptr %tokens196, i64 %idx_plus1199
  %load_ptr_elem201 = load ptr, ptr %list_index200, align 8
  %load_value202522 = bitcast ptr %load_ptr_elem201 to ptr
  %value203 = load ptr, ptr %load_value202522, align 8
  store ptr %value203, ptr %task_key, align 8
  %current204 = load double, ptr %current, align 8
  %addtmp205 = fadd double %current204, 1.000000e+00
  store double %addtmp205, ptr %current, align 8
  %current209 = load double, ptr %current, align 8
  %total210 = load double, ptr %total, align 8
  %getmp211 = fcmp oge double %current209, %total210
  br i1 %getmp211, label %common.ret, label %logic_rhs212

cont208:                                          ; preds = %logic_rhs212
  %current225 = load double, ptr %current, align 8
  %addtmp226 = fadd double %current225, 1.000000e+00
  store double %addtmp226, ptr %current, align 8
  %task_key230 = load ptr, ptr %task_key, align 8
  %strcmp_call231 = call i32 @strcmp(ptr %task_key230, ptr @str_literal.38)
  %streq232 = icmp eq i32 %strcmp_call231, 0
  br i1 %streq232, label %then227, label %else228

logic_rhs212:                                     ; preds = %cont185
  %tokens214 = load ptr, ptr %tokens, align 8
  %current215 = load double, ptr %current, align 8
  %number216 = fptosi double %current215 to i64
  %idx_plus1217 = add i64 %number216, 1
  %list_index218 = getelementptr inbounds double, ptr %tokens214, i64 %idx_plus1217
  %load_ptr_elem219 = load ptr, ptr %list_index218, align 8
  %load_kind220 = getelementptr inbounds i64, ptr %load_ptr_elem219, i64 1
  %kind221 = load ptr, ptr %load_kind220, align 8
  %strcmp_call222 = call i32 @strcmp(ptr %kind221, ptr @str_literal.36)
  %strneq223 = icmp ne i32 %strcmp_call222, 0
  br i1 %strneq223, label %common.ret, label %cont208

then227:                                          ; preds = %cont208
  %current236 = load double, ptr %current, align 8
  %total237 = load double, ptr %total, align 8
  %getmp238 = fcmp oge double %current236, %total237
  br i1 %getmp238, label %common.ret, label %logic_rhs239

else228:                                          ; preds = %cont208
  %task_key265 = load ptr, ptr %task_key, align 8
  %strcmp_call266 = call i32 @strcmp(ptr %task_key265, ptr @str_literal.41)
  %streq267 = icmp eq i32 %strcmp_call266, 0
  br i1 %streq267, label %then262, label %common.ret

cont229:                                          ; preds = %then296, %then306, %cont235
  %current328 = load double, ptr %current, align 8
  %total329 = load double, ptr %total, align 8
  %lttmp330 = fcmp olt double %current328, %total329
  br i1 %lttmp330, label %logic_rhs331, label %while.cond163

cont235:                                          ; preds = %logic_rhs239
  %tokens252 = load ptr, ptr %tokens, align 8
  %current253 = load double, ptr %current, align 8
  %number254 = fptosi double %current253 to i64
  %idx_plus1255 = add i64 %number254, 1
  %list_index256 = getelementptr inbounds double, ptr %tokens252, i64 %idx_plus1255
  %load_ptr_elem257 = load ptr, ptr %list_index256, align 8
  %load_value258523 = bitcast ptr %load_ptr_elem257 to ptr
  %value259 = load ptr, ptr %load_value258523, align 8
  store ptr %value259, ptr %task_text, align 8
  store i1 true, ptr %seen_text, align 1
  %current260 = load double, ptr %current, align 8
  %addtmp261 = fadd double %current260, 1.000000e+00
  store double %addtmp261, ptr %current, align 8
  br label %cont229

logic_rhs239:                                     ; preds = %then227
  %tokens241 = load ptr, ptr %tokens, align 8
  %current242 = load double, ptr %current, align 8
  %number243 = fptosi double %current242 to i64
  %idx_plus1244 = add i64 %number243, 1
  %list_index245 = getelementptr inbounds double, ptr %tokens241, i64 %idx_plus1244
  %load_ptr_elem246 = load ptr, ptr %list_index245, align 8
  %load_kind247 = getelementptr inbounds i64, ptr %load_ptr_elem246, i64 1
  %kind248 = load ptr, ptr %load_kind247, align 8
  %strcmp_call249 = call i32 @strcmp(ptr %kind248, ptr @str_literal.39)
  %strneq250 = icmp ne i32 %strcmp_call249, 0
  br i1 %strneq250, label %common.ret, label %cont235

then262:                                          ; preds = %else228
  %current271 = load double, ptr %current, align 8
  %total272 = load double, ptr %total, align 8
  %getmp273 = fcmp oge double %current271, %total272
  br i1 %getmp273, label %common.ret, label %cont270

cont270:                                          ; preds = %then262
  %tokens274 = load ptr, ptr %tokens, align 8
  %current275 = load double, ptr %current, align 8
  %number276 = fptosi double %current275 to i64
  %idx_plus1277 = add i64 %number276, 1
  %list_index278 = getelementptr inbounds double, ptr %tokens274, i64 %idx_plus1277
  %load_ptr_elem279 = load ptr, ptr %list_index278, align 8
  store ptr %load_ptr_elem279, ptr %bool_token, align 8
  %bool_token283 = load ptr, ptr %bool_token, align 8
  %load_kind284 = getelementptr inbounds i64, ptr %bool_token283, i64 1
  %kind285 = load ptr, ptr %load_kind284, align 8
  %strcmp_call286 = call i32 @strcmp(ptr %kind285, ptr @str_literal.43)
  %streq287 = icmp eq i32 %strcmp_call286, 0
  br i1 %streq287, label %then280, label %logic_rhs288

then280:                                          ; preds = %cont270, %logic_rhs288
  %bool_token299 = load ptr, ptr %bool_token, align 8
  %load_value300524 = bitcast ptr %bool_token299 to ptr
  %value301 = load ptr, ptr %load_value300524, align 8
  %strcmp_call302 = call i32 @strcmp(ptr %value301, ptr @str_literal.45)
  %streq303 = icmp eq i32 %strcmp_call302, 0
  br i1 %streq303, label %then296, label %else297

logic_rhs288:                                     ; preds = %cont270
  %bool_token290 = load ptr, ptr %bool_token, align 8
  %load_kind291 = getelementptr inbounds i64, ptr %bool_token290, i64 1
  %kind292 = load ptr, ptr %load_kind291, align 8
  %strcmp_call293 = call i32 @strcmp(ptr %kind292, ptr @str_literal.44)
  %streq294 = icmp eq i32 %strcmp_call293, 0
  br i1 %streq294, label %then280, label %common.ret

then296:                                          ; preds = %then280
  store i1 true, ptr %task_completed, align 1
  store i1 true, ptr %seen_completed, align 1
  %current304 = load double, ptr %current, align 8
  %addtmp305 = fadd double %current304, 1.000000e+00
  store double %addtmp305, ptr %current, align 8
  br label %cont229

else297:                                          ; preds = %then280
  %bool_token309 = load ptr, ptr %bool_token, align 8
  %load_value310525 = bitcast ptr %bool_token309 to ptr
  %value311 = load ptr, ptr %load_value310525, align 8
  %strcmp_call312 = call i32 @strcmp(ptr %value311, ptr @str_literal.46)
  %streq313 = icmp eq i32 %strcmp_call312, 0
  br i1 %streq313, label %then306, label %common.ret

then306:                                          ; preds = %else297
  store i1 false, ptr %task_completed, align 1
  store i1 true, ptr %seen_completed, align 1
  %current314 = load double, ptr %current, align 8
  %addtmp315 = fadd double %current314, 1.000000e+00
  store double %addtmp315, ptr %current, align 8
  br label %cont229

then325:                                          ; preds = %logic_rhs331
  %current343 = load double, ptr %current, align 8
  %addtmp344 = fadd double %current343, 1.000000e+00
  store double %addtmp344, ptr %current, align 8
  br label %while.cond163

logic_rhs331:                                     ; preds = %cont229
  %tokens333 = load ptr, ptr %tokens, align 8
  %current334 = load double, ptr %current, align 8
  %number335 = fptosi double %current334 to i64
  %idx_plus1336 = add i64 %number335, 1
  %list_index337 = getelementptr inbounds double, ptr %tokens333, i64 %idx_plus1336
  %load_ptr_elem338 = load ptr, ptr %list_index337, align 8
  %load_kind339 = getelementptr inbounds i64, ptr %load_ptr_elem338, i64 1
  %kind340 = load ptr, ptr %load_kind339, align 8
  %strcmp_call341 = call i32 @strcmp(ptr %kind340, ptr @str_literal.50)
  %streq342 = icmp eq i32 %strcmp_call341, 0
  br i1 %streq342, label %then325, label %while.cond163

cont347:                                          ; preds = %logic_rhs351
  %current364 = load double, ptr %current, align 8
  %addtmp365 = fadd double %current364, 1.000000e+00
  store double %addtmp365, ptr %current, align 8
  %seen_text369 = load i1, ptr %seen_text, align 1
  %not_op = icmp eq i1 %seen_text369, false
  br i1 %not_op, label %common.ret, label %cont368

logic_rhs351:                                     ; preds = %while.cont165
  %tokens353 = load ptr, ptr %tokens, align 8
  %current354 = load double, ptr %current, align 8
  %number355 = fptosi double %current354 to i64
  %idx_plus1356 = add i64 %number355, 1
  %list_index357 = getelementptr inbounds double, ptr %tokens353, i64 %idx_plus1356
  %load_ptr_elem358 = load ptr, ptr %list_index357, align 8
  %load_kind359 = getelementptr inbounds i64, ptr %load_ptr_elem358, i64 1
  %kind360 = load ptr, ptr %load_kind359, align 8
  %strcmp_call361 = call i32 @strcmp(ptr %kind360, ptr @str_literal.51)
  %strneq362 = icmp ne i32 %strcmp_call361, 0
  br i1 %strneq362, label %common.ret, label %cont347

cont368:                                          ; preds = %cont347
  %parsed_tasks370 = load ptr, ptr %parsed_tasks, align 8
  %len_load = load double, ptr %parsed_tasks370, align 8
  %len_to_i64 = fptosi double %len_load to i64
  %needed_slots = add i64 %len_to_i64, 2
  %push_bytes = mul i64 8, %needed_slots
  %realloc_list_push = call ptr @realloc(ptr %parsed_tasks370, i64 %push_bytes)
  store ptr %realloc_list_push, ptr %parsed_tasks, align 8
  %push_idx = add i64 %len_to_i64, 1
  %push_elem_ptr = getelementptr inbounds double, ptr %realloc_list_push, i64 %push_idx
  %malloc_obj = call ptr @malloc(i64 16)
  %task_completed371 = load i1, ptr %task_completed, align 1
  %field_completed526 = bitcast ptr %malloc_obj to ptr
  store i1 %task_completed371, ptr %field_completed526, align 1
  %task_text372 = load ptr, ptr %task_text, align 8
  %field_text = getelementptr inbounds i64, ptr %malloc_obj, i64 1
  store ptr %task_text372, ptr %field_text, align 8
  store ptr %malloc_obj, ptr %push_elem_ptr, align 8
  %len_inc = add i64 %len_to_i64, 1
  %len_to_f64 = sitofp i64 %len_inc to double
  store double %len_to_f64, ptr %realloc_list_push, align 8
  %current376 = load double, ptr %current, align 8
  %total377 = load double, ptr %total, align 8
  %lttmp378 = fcmp olt double %current376, %total377
  br i1 %lttmp378, label %logic_rhs379, label %while.cond128

then373:                                          ; preds = %logic_rhs379
  %current392 = load double, ptr %current, align 8
  %addtmp393 = fadd double %current392, 1.000000e+00
  store double %addtmp393, ptr %current, align 8
  br label %while.cond128

logic_rhs379:                                     ; preds = %cont368
  %tokens381 = load ptr, ptr %tokens, align 8
  %current382 = load double, ptr %current, align 8
  %number383 = fptosi double %current382 to i64
  %idx_plus1384 = add i64 %number383, 1
  %list_index385 = getelementptr inbounds double, ptr %tokens381, i64 %idx_plus1384
  %load_ptr_elem386 = load ptr, ptr %list_index385, align 8
  %load_kind387 = getelementptr inbounds i64, ptr %load_ptr_elem386, i64 1
  %kind388 = load ptr, ptr %load_kind387, align 8
  %strcmp_call389 = call i32 @strcmp(ptr %kind388, ptr @str_literal.54)
  %streq390 = icmp eq i32 %strcmp_call389, 0
  br i1 %streq390, label %then373, label %while.cond128

cont396:                                          ; preds = %logic_rhs400
  %current413 = load double, ptr %current, align 8
  %addtmp414 = fadd double %current413, 1.000000e+00
  store double %addtmp414, ptr %current, align 8
  store i1 true, ptr %has_tasks, align 1
  %parsed_tasks415 = load ptr, ptr %parsed_tasks, align 8
  store ptr %parsed_tasks415, ptr %tasks, align 8
  br label %cont66

logic_rhs400:                                     ; preds = %while.cont130
  %tokens402 = load ptr, ptr %tokens, align 8
  %current403 = load double, ptr %current, align 8
  %number404 = fptosi double %current403 to i64
  %idx_plus1405 = add i64 %number404, 1
  %list_index406 = getelementptr inbounds double, ptr %tokens402, i64 %idx_plus1405
  %load_ptr_elem407 = load ptr, ptr %list_index406, align 8
  %load_kind408 = getelementptr inbounds i64, ptr %load_ptr_elem407, i64 1
  %kind409 = load ptr, ptr %load_kind408, align 8
  %strcmp_call410 = call i32 @strcmp(ptr %kind409, ptr @str_literal.55)
  %strneq411 = icmp ne i32 %strcmp_call410, 0
  br i1 %strneq411, label %common.ret, label %cont396

then416:                                          ; preds = %else65
  %2 = fcmp oge double %current108, %total109
  br i1 %2, label %common.ret, label %cont421

cont421:                                          ; preds = %then416
  %tokens428 = load ptr, ptr %tokens, align 8
  %current429 = load double, ptr %current, align 8
  %number430 = fptosi double %current429 to i64
  %idx_plus1431 = add i64 %number430, 1
  %list_index432 = getelementptr inbounds double, ptr %tokens428, i64 %idx_plus1431
  %load_ptr_elem433 = load ptr, ptr %list_index432, align 8
  %load_kind434 = getelementptr inbounds i64, ptr %load_ptr_elem433, i64 1
  %kind435 = load ptr, ptr %load_kind434, align 8
  %strcmp_call436 = call i32 @strcmp(ptr %kind435, ptr @str_literal.58)
  %streq437 = icmp eq i32 %strcmp_call436, 0
  br i1 %streq437, label %then425, label %logic_rhs438

then425:                                          ; preds = %cont421, %logic_rhs438
  %current451 = load double, ptr %current, align 8
  %addtmp452 = fadd double %current451, 1.000000e+00
  store double %addtmp452, ptr %current, align 8
  br label %cont66

logic_rhs438:                                     ; preds = %cont421
  %tokens440 = load ptr, ptr %tokens, align 8
  %current441 = load double, ptr %current, align 8
  %number442 = fptosi double %current441 to i64
  %idx_plus1443 = add i64 %number442, 1
  %list_index444 = getelementptr inbounds double, ptr %tokens440, i64 %idx_plus1443
  %load_ptr_elem445 = load ptr, ptr %list_index444, align 8
  %load_kind446 = getelementptr inbounds i64, ptr %load_ptr_elem445, i64 1
  %kind447 = load ptr, ptr %load_kind446, align 8
  %strcmp_call448 = call i32 @strcmp(ptr %kind447, ptr @str_literal.59)
  %streq449 = icmp eq i32 %strcmp_call448, 0
  br i1 %streq449, label %then425, label %common.ret

then456:                                          ; preds = %logic_rhs462
  %current475 = load double, ptr %current, align 8
  %addtmp476 = fadd double %current475, 1.000000e+00
  store double %addtmp476, ptr %current, align 8
  br label %while.cond

logic_rhs462:                                     ; preds = %cont66
  %tokens464 = load ptr, ptr %tokens, align 8
  %current465 = load double, ptr %current, align 8
  %number466 = fptosi double %current465 to i64
  %idx_plus1467 = add i64 %number466, 1
  %list_index468 = getelementptr inbounds double, ptr %tokens464, i64 %idx_plus1467
  %load_ptr_elem469 = load ptr, ptr %list_index468, align 8
  %load_kind470 = getelementptr inbounds i64, ptr %load_ptr_elem469, i64 1
  %kind471 = load ptr, ptr %load_kind470, align 8
  %strcmp_call472 = call i32 @strcmp(ptr %kind471, ptr @str_literal.61)
  %streq473 = icmp eq i32 %strcmp_call472, 0
  br i1 %streq473, label %then456, label %while.cond

logic_rhs483:                                     ; preds = %while.cont
  %tokens485 = load ptr, ptr %tokens, align 8
  %current486 = load double, ptr %current, align 8
  %number487 = fptosi double %current486 to i64
  %idx_plus1488 = add i64 %number487, 1
  %list_index489 = getelementptr inbounds double, ptr %tokens485, i64 %idx_plus1488
  %load_ptr_elem490 = load ptr, ptr %list_index489, align 8
  %load_kind491 = getelementptr inbounds i64, ptr %load_ptr_elem490, i64 1
  %kind492 = load ptr, ptr %load_kind491, align 8
  %strcmp_call493 = call i32 @strcmp(ptr %kind492, ptr @str_literal.62)
  %strneq494 = icmp ne i32 %strcmp_call493, 0
  %has_name499 = load i1, ptr %has_name, align 1
  %not_op500 = icmp eq i1 %has_name499, false
  %or.cond = select i1 %strneq494, i1 true, i1 %not_op500
  br i1 %or.cond, label %common.ret, label %cont503

cont503:                                          ; preds = %logic_rhs483
  %malloc_obj506 = call ptr @malloc(i64 16)
  %name507 = load ptr, ptr %name, align 8
  %field_name527 = bitcast ptr %malloc_obj506 to ptr
  store ptr %name507, ptr %field_name527, align 8
  %tasks508 = load ptr, ptr %tasks, align 8
  %field_tasks = getelementptr inbounds i64, ptr %malloc_obj506, i64 1
  store ptr %tasks508, ptr %field_tasks, align 8
  br label %common.ret
}

declare ptr @malloc(i64)

declare i64 @strlen(ptr)

declare ptr @strcpy(ptr, ptr)

declare ptr @strcat(ptr, ptr)

declare i32 @strcmp(ptr, ptr)

declare ptr @realloc(ptr, i64)

declare ptr @strstr(ptr, ptr)

declare i32 @printf(ptr, ...)

declare ptr @create_web_helper()

declare ptr @qs_obj_new()

define ptr @inline_fn_0(ptr %0) {
entry:
  %user = alloca ptr, align 8
  %page = alloca ptr, align 8
  %path = alloca ptr, align 8
  %session = alloca ptr, align 8
  %body = alloca ptr, align 8
  %req = alloca ptr, align 8
  store ptr %0, ptr %req, align 8
  %web = alloca ptr, align 8
  %web_env_ptr = load ptr, ptr @_MergedGlobals, align 8
  %web_env_val = load ptr, ptr %web_env_ptr, align 8
  store ptr %web_env_val, ptr %web, align 8
  %sessions = alloca ptr, align 8
  %sessions_env_ptr = load ptr, ptr getelementptr inbounds (<{ ptr, ptr, ptr }>, ptr @_MergedGlobals, i32 0, i32 1), align 8
  %sessions_env_val = load ptr, ptr %sessions_env_ptr, align 8
  store ptr %sessions_env_val, ptr %sessions, align 8
  %maybe_user = alloca ptr, align 8
  %maybe_user_env_ptr = load ptr, ptr getelementptr inbounds (<{ ptr, ptr, ptr }>, ptr @_MergedGlobals, i32 0, i32 2), align 8
  %maybe_user_env_val = load ptr, ptr %maybe_user_env_ptr, align 8
  store ptr %maybe_user_env_val, ptr %maybe_user, align 8
  %req1 = load ptr, ptr %req, align 8
  %get_body_call = call ptr @get_request_body(ptr %req1)
  store ptr %get_body_call, ptr %body, align 8
  %req2 = load ptr, ptr %req, align 8
  %get_path_call = call ptr @get_request_path(ptr %req2)
  %strcmp_call = call i32 @strcmp(ptr %get_path_call, ptr @str_literal.67)
  %streq = icmp eq i32 %strcmp_call, 0
  br i1 %streq, label %then, label %then12

then:                                             ; preds = %entry
  %body3 = load ptr, ptr %body, align 8
  %neq_nil = icmp ne ptr %body3, null
  br i1 %neq_nil, label %then4, label %else5

common.ret:                                       ; preds = %else52, %then51, %else5, %then4
  %common.ret.op = phi ptr [ %web_call, %then4 ], [ %web_call11, %else5 ], [ %web_call57, %then51 ], [ %web_call58, %else52 ]
  ret ptr %common.ret.op

then4:                                            ; preds = %then
  %rand_call = call i32 @rand()
  %rand_f64 = sitofp i32 %rand_call to double
  %rand_div = fdiv double %rand_f64, 0x41DFFFFFFFC00000
  %malloc_buf = call ptr @malloc(i64 128)
  %sprintf_call = call i32 (ptr, ptr, ...) @sprintf(ptr %malloc_buf, ptr @fmt_str, double %rand_div)
  store ptr %malloc_buf, ptr %session, align 8
  %sessions6 = load ptr, ptr %sessions, align 8
  %session7 = load ptr, ptr %session, align 8
  %malloc_obj = call ptr @malloc(i64 16)
  %body8 = load ptr, ptr %body, align 8
  %field_name59 = bitcast ptr %malloc_obj to ptr
  store ptr %body8, ptr %field_name59, align 8
  %malloc = call ptr @malloc(i64 8)
  %len_ptr60 = bitcast ptr %malloc to ptr
  store double 0.000000e+00, ptr %len_ptr60, align 8
  %field_tasks = getelementptr inbounds i64, ptr %malloc_obj, i64 1
  store ptr %malloc, ptr %field_tasks, align 8
  call void @qs_obj_insert_str(ptr %sessions6, ptr %session7, ptr %malloc_obj)
  %session9 = load ptr, ptr %session, align 8
  %len1 = call i64 @strlen(ptr @str_literal.68)
  %len2 = call i64 @strlen(ptr %session9)
  %len_sum = add i64 %len1, %len2
  %total_len = add i64 %len_sum, 1
  %malloc_buf10 = call ptr @malloc(i64 %total_len)
  %strcpy_call = call ptr @strcpy(ptr %malloc_buf10, ptr @str_literal.68)
  %strcat_call = call ptr @strcat(ptr %malloc_buf10, ptr %session9)
  %web_call = call ptr @web_text(ptr %malloc_buf10)
  br label %common.ret

else5:                                            ; preds = %then
  %web_call11 = call ptr @web_text(ptr @str_literal.69)
  br label %common.ret

then12:                                           ; preds = %entry
  %req15 = load ptr, ptr %req, align 8
  %get_path_call16 = call ptr @get_request_path(ptr %req15)
  store ptr %get_path_call16, ptr %path, align 8
  %path20 = load ptr, ptr %path, align 8
  %strlen_call = call i64 @strlen(ptr @str_literal.71)
  %path21 = load ptr, ptr %path, align 8
  %strlen_call22 = call i64 @strlen(ptr %path21)
  %ends_offset = sub i64 %strlen_call22, %strlen_call
  %hay_end_ptr = getelementptr inbounds i8, ptr %path20, i64 %ends_offset
  %needle_len_i32 = trunc i64 %strlen_call to i32
  %strncmp_suffix = call i32 @strncmp(ptr %hay_end_ptr, ptr @str_literal.70, i32 %needle_len_i32)
  %ends_with_bool = icmp eq i32 %strncmp_suffix, 0
  br i1 %ends_with_bool, label %then17, label %cont19

then17:                                           ; preds = %then12
  %path23 = load ptr, ptr %path, align 8
  %len124 = call i64 @strlen(ptr %path23)
  %len225 = call i64 @strlen(ptr @str_literal.72)
  %len_sum26 = add i64 %len124, %len225
  %total_len27 = add i64 %len_sum26, 1
  %malloc_buf28 = call ptr @malloc(i64 %total_len27)
  %strcpy_call29 = call ptr @strcpy(ptr %malloc_buf28, ptr %path23)
  %strcat_call30 = call ptr @strcat(ptr %malloc_buf28, ptr @str_literal.72)
  store ptr %malloc_buf28, ptr %path, align 8
  br label %cont19

cont19:                                           ; preds = %then12, %then17
  %path31 = load ptr, ptr %path, align 8
  %len132 = call i64 @strlen(ptr @str_literal.73)
  %len233 = call i64 @strlen(ptr %path31)
  %len_sum34 = add i64 %len132, %len233
  %total_len35 = add i64 %len_sum34, 1
  %malloc_buf36 = call ptr @malloc(i64 %total_len35)
  %strcpy_call37 = call ptr @strcpy(ptr %malloc_buf36, ptr @str_literal.73)
  %strcat_call38 = call ptr @strcat(ptr %malloc_buf36, ptr %path31)
  %io_read_call = call ptr @io_read_file(ptr %malloc_buf36)
  store ptr %io_read_call, ptr %page, align 8
  %sessions39 = load ptr, ptr %sessions, align 8
  %req40 = load ptr, ptr %req, align 8
  %get_body_call41 = call ptr @get_request_body(ptr %req40)
  %option_default_has_value = icmp ne ptr %get_body_call41, null
  %option_default_select = select i1 %option_default_has_value, ptr %get_body_call41, ptr @str_literal.74
  %obj_get = call ptr @qs_obj_get_str(ptr %sessions39, ptr %option_default_select)
  %malloc_obj42 = call ptr @malloc(i64 16)
  %field_name4361 = bitcast ptr %malloc_obj42 to ptr
  store ptr @str_literal.75, ptr %field_name4361, align 8
  %malloc44 = call ptr @malloc(i64 8)
  %len_ptr4562 = bitcast ptr %malloc44 to ptr
  store double 0.000000e+00, ptr %len_ptr4562, align 8
  %field_tasks46 = getelementptr inbounds i64, ptr %malloc_obj42, i64 1
  store ptr %malloc44, ptr %field_tasks46, align 8
  %option_default_has_value47 = icmp ne ptr %obj_get, null
  %option_default_select48 = select i1 %option_default_has_value47, ptr %obj_get, ptr %malloc_obj42
  store ptr %option_default_select48, ptr %user, align 8
  %page49 = load ptr, ptr %page, align 8
  %neq_nil50 = icmp ne ptr %page49, null
  br i1 %neq_nil50, label %then51, label %else52

then51:                                           ; preds = %cont19
  %printf_str = call i32 (ptr, ...) @printf(ptr @fmt_s.77, ptr @str_literal.76)
  %page54 = load ptr, ptr %page, align 8
  %user55 = load ptr, ptr %user, align 8
  %load_name63 = bitcast ptr %user55 to ptr
  %name = load ptr, ptr %load_name63, align 8
  %str_replace_call = call ptr @qs_str_replace(ptr %page54, ptr @str_literal.78, ptr %name)
  %str_replace_call56 = call ptr @qs_str_replace(ptr %str_replace_call, ptr @str_literal.79, ptr @str_literal.80)
  %web_call57 = call ptr @web_page(ptr %str_replace_call56)
  br label %common.ret

else52:                                           ; preds = %cont19
  %web_call58 = call ptr @web_text(ptr @str_literal.81)
  br label %common.ret
}

declare ptr @get_request_body(ptr)

declare ptr @get_request_path(ptr)

declare i32 @rand()

declare i32 @sprintf(ptr, ptr, ...)

declare void @qs_obj_insert_str(ptr, ptr, ptr)

declare ptr @web_text(ptr)

declare i32 @strncmp(ptr, ptr, i32)

declare ptr @io_read_file(ptr)

declare ptr @qs_obj_get_str(ptr, ptr)

declare ptr @qs_str_replace(ptr, ptr, ptr)

declare ptr @web_page(ptr)

declare void @qs_listen_with_callback(i32, ptr)

declare i64 @atoi(ptr)

declare ptr @qs_str_split(ptr, ptr)

declare ptr @fopen(ptr, ptr)

declare i64 @fread(ptr, i64, i64, ptr)

declare i64 @fwrite(ptr, i64, i64, ptr)

declare i32 @fclose(ptr)

declare ptr @get_stdin()

declare ptr @create_request_object(ptr, ptr, ptr, ptr, ptr)

declare ptr @get_request_method(ptr)

declare ptr @get_request_query(ptr)

declare ptr @get_request_headers(ptr)

declare ptr @create_range_builder()

declare ptr @create_range_builder_to(ptr, double)

declare ptr @create_range_builder_from(ptr, double)

declare ptr @create_range_builder_step(ptr, double)

declare double @range_builder_get_from(ptr)

declare double @range_builder_get_to(ptr)

declare double @range_builder_get_step(ptr)

declare double @io_write_file(ptr, ptr)

declare ptr @web_file(ptr)

declare ptr @web_json(ptr)

declare ptr @web_error_text(i32, ptr)

declare ptr @web_error_page(i32, ptr)

declare ptr @web_redirect(ptr, i1)
