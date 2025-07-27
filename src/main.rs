//! #![allow(unused_variables)]
//! #![allow(dead_code)]
//! #![allow(unused_mut)]
//! #![allow(unused_imports)]

use crate::TokenKind::*;
unsafe extern "C" {
    fn strcmp(a: *const i8, b: *const i8) -> i32;
    fn printf(fmt: *const i8, ...) -> i32;
    fn malloc(size: usize) -> *mut std::ffi::c_void;
    fn realloc(ptr: *mut std::ffi::c_void, size: usize) -> *mut std::ffi::c_void;
    fn memcpy(
        dest: *mut std::ffi::c_void,
        src: *const std::ffi::c_void,
        n: usize,
    ) -> *mut std::ffi::c_void;
    fn strcpy(dest: *mut i8, src: *const i8) -> *mut i8;
    fn sprintf(buf: *mut i8, fmt: *const i8, ...) -> i32;
    fn strcat(dest: *mut i8, src: *const i8) -> *mut i8;
    fn strlen(s: *const i8) -> usize;
    fn rand() -> i32;
    fn time(t: *mut i64) -> i64;
    fn srand(seed: u32);
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

}
use inkwell::AddressSpace;
use inkwell::OptimizationLevel;
use inkwell::builder::{Builder, BuilderError};
use inkwell::context;
use inkwell::execution_engine::{ExecutionEngine, JitFunction};
use inkwell::module::Module;
use inkwell::types::{BasicType, BasicTypeEnum};
use inkwell::values::{
    BasicMetadataValueEnum, BasicValue as _, BasicValueEnum, FunctionValue, PointerValue,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fmt::{Debug, Display, Formatter};
use std::fs;
use std::mem;
use std::ptr;

use libc::{c_void, FILE};

unsafe extern "C" {
    static mut stdin: *mut FILE;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn get_stdin() -> *mut c_void {
    unsafe { stdin as *mut c_void }
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
    Slash,
    Str(String),
    Identifier(String),
    And,
    Object,
    Maybe,
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
    Super,
    This,
    True,
    Let,
    While,
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
    Grouping(Box<Expr>),
    Get(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    List(Vec<Expr>),
    Object(String, HashMap<String, Expr>),
    Block(Vec<Instruction>),
}

#[derive(Debug, Clone)]
enum Instruction {
    Let {
        name: String,
        value: Expr,
        type_hint: Type,
    },
    Assign(String, Expr, Option<Type>),
    Println(Expr),
    Return(Expr),
    If {
        condition: Expr,
        then: Vec<Instruction>,
        elses: Option<Box<Instruction>>,
    },
    While {
        condition: Expr,
        body: Vec<Instruction>,
    },
    For {
        init: Box<Instruction>,
        condition: Expr,
        step: Box<Instruction>,
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
    Nothing,
}

#[derive(Clone)]
enum Value {
    Num(f64),
    Str(String),
    /// Special return value used to signal early exit from functions
    Return(Box<Value>),
    Object(HashMap<String, Value>),
    Bool(bool),
    Function(Vec<(String, String)>, Vec<Instruction>),
    List(Vec<Value>),
    Nil,
}

#[derive(Default, Clone, Debug)]
enum Reqs {
    #[default]
    Get,
    Post,
}

#[derive(Default, Clone, Debug)]
enum PathPart {
    #[default]
    Dynamic,
    Static(String),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Num(l), Value::Num(r)) => l == r,
            (Value::Str(l), Value::Str(r)) => l == r,
            (Value::Bool(l), Value::Bool(r)) => l == r,
            (Value::Function(l, _), Value::Function(r, _)) => l == r,
            (Value::List(l), Value::List(r)) => l == r,
            (Value::Nil, Value::Nil) => true,
            _ => false,
        }
    }
}

impl Debug for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Num(n) => write!(f, "Num({n})"),
            Self::Str(s) => write!(f, "Str({s})"),
            Self::Return(v) => write!(f, "{:?}", *v),
            Self::Bool(b) => write!(f, "Bool({b})"),
            Self::Function(p, _) => write!(f, "Function({})", p.len()),
            Self::List(l) => write!(
                f,
                "[{}]",
                l.iter()
                    .map(move |f| format!("{:?}", f))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            Self::Object(o) => write!(f, "{:?}", o),
            Self::Nil => write!(f, "nil"),
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Num(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Return(v) => write!(f, "{:?}", *v),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Function(p, _) => write!(f, "{}", p.len()),
            Self::List(l) => write!(
                f,
                "[{}]",
                l.iter()
                    .map(move |f| format!("{:?}", f))
                    .collect::<Vec<String>>()
                    .join(", ")
            ),
            Self::Object(o) => write!(f, "{:?}", o),
            Self::Nil => write!(f, "nil"),
        }
    }
}

impl Value {
    fn value(&self) -> String {
        match self {
            Value::Num(n) => n.to_string(),
            Value::Str(s) => s.to_string(),
            Value::Return(inner) => inner.value(),
            Value::Function(_, _) => "function block".to_string(),
            Value::List(vals) => {
                let inner = vals
                    .iter()
                    .map(|v| v.value())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("[{inner}]")
            }
            Value::Object(o) => format!("{:?}", o),
            Value::Nil => "nil".to_string(),
            Value::Bool(b) => b.to_string(),
        }
    }
}

#[derive(Default, Clone)]
struct PreCtx {
    var_types: HashMap<String, Type>,
    types: HashMap<String, HashMap<String, Type>>,
}

struct Parser {
    tokens: Vec<Token>,
    current: usize, // index into `tokens`
    pctx: PreCtx,
    current_return_type: Option<Type>,
    inside_maybe: bool,
    saw_non_nil_return: bool,
    saw_nil_return: bool,
}

#[derive(Debug, Clone)]
enum Type {
    Num,
    Str,
    Bool,
    Nil,
    Io,
    List(Box<Type>),
    Option(Box<Type>),
    Custom(HashMap<String, Type>),
    Function(Vec<(String, String)>, Box<Type>),
}

impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Type::Num, Type::Num)
            | (Type::Str, Type::Str)
            | (Type::Bool, Type::Bool)
            | (Type::Nil, Type::Nil)
            | (Type::Io, Type::Io) => true,

            (Type::List(left), Type::List(right)) | (Type::Option(left), Type::Option(right)) => {
                left == right
            }

            (Type::Function(params_l, ret_l), Type::Function(params_r, ret_r)) => {
                params_l == params_r && ret_l == ret_r
            }

            (Type::Custom(map_l), Type::Custom(map_r)) => {
                // Compare as maps: same length and all corresponding entries equal
                if map_l.len() != map_r.len() {
                    return false;
                }
                for (key, val_l) in map_l.iter() {
                    match map_r.get(key) {
                        Some(val_r) if *val_l == *val_r => continue,
                        _ => return false,
                    }
                }
                true
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
            inside_maybe: false,
            saw_non_nil_return: false,
            saw_nil_return: false,
        }
    }

    // ───── entry point ─────

    fn parse_program(&mut self) -> Result<Vec<Instruction>, String> {
        let mut prgm = Vec::new();
        self.pctx.var_types.insert("io".to_string(), Type::Io);
        while !self.is_at_end() {
            prgm.push(self.parse_statement()?);
        }
        Ok(prgm)
    }

    fn parse_statement(&mut self) -> Result<Instruction, String> {
        // Handle return statements with type inference and consistency checking
        if self.match_kind(TokenKind::Return) {
            let expr = self.expression()?;
            let ret_type = get_type_of_expr(&expr, &self.pctx)?;
            // Track explicit nil/non-nil returns for this function
            if ret_type == Type::Nil {
                self.saw_nil_return = true;
            } else {
                self.saw_non_nil_return = true;
            }
            // Unify return types: allow Nil and uniform type => Option(inner)
            let new_ret_type = if let Some(old) = &self.current_return_type {
                if *old == ret_type {
                    old
                } else if *old == Type::Nil {
                    &Type::Option(Box::new(ret_type))
                } else if ret_type == Type::Nil {
                    &Type::Option(Box::new(old.clone()))
                } else {
                    return Err(format!(
                        "Mismatched return types in function: {:?} vs {:?}",
                        old, ret_type,
                    ));
                }
            } else {
                &ret_type
            };
            self.current_return_type = Some(new_ret_type.clone());
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Return(expr))
        } else if self.match_kind(TokenKind::For) {
            let start = self.parse_statement()?;
            let cond = self.expression()?;
            self.consume(Semicolon, "Expected semicolon after condition")?;
            let step = self.parse_statement()?;
            let block = self.parse_statement()?;
            Ok(Instruction::For {
                init: Box::new(start),
                condition: cond,
                step: Box::new(step),
                body: vec![block],
            })
        } else if self.match_kind(TokenKind::Maybe) {
            let prev_inside = self.inside_maybe;
            self.inside_maybe = true;
            let maybe = self.expression()?;
            let block = self.parse_statement()?;
            let mut once_else = None;
            if self.match_kind(TokenKind::Else) {
                once_else = Some(Box::new(self.parse_statement()?));
            }
            let peekd = self.peek().line;

            self.inside_maybe = prev_inside;
            Ok(Instruction::Maybe(maybe, Box::new(block), once_else))
        } else if self.match_kind(TokenKind::LBrace) {
            // Static type scope for block: save outer types
            let saved_types = self.pctx.var_types.clone();
            let mut stmts = Vec::new();
            while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
                stmts.push(self.parse_statement()?);
            }
            self.consume(TokenKind::RBrace, "Expected '}' after block")?;
            // Restore outer static types after block
            self.pctx.var_types = saved_types;

            Ok(Instruction::Block(stmts))
        } else if self.match_kind(TokenKind::Print) || self.match_kind(TokenKind::Reprint) {
            let prkind = self.previous().clone();
            let expr = self.expression()?;
            // Static type checking for print expression
            let _expr_type = get_type_of_expr(&expr, &self.pctx)?;

            if !self.inside_maybe {
                match _expr_type {
                    Type::Nil | Type::Option(_) => {
                        return Err(
                            "Cannot use a value that might be nil outside of a `maybe` block."
                                .into(),
                        );
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
                let act_typ = match self.peek().kind {
                    Identifier(r) => match r.as_str() {
                        "Str" => Type::Str,
                        "Num" => Type::Num,
                        "Bool" => Type::Bool,
                        l => {
                            let Some(a) = self.pctx.types.get(l) else {
                                return Err(format!("Couldn't find type {l}"));
                            };
                            Type::Custom(a.clone())
                        }
                    },
                    LBrack => {
                        self.advance();
                        let ret = match self.peek().kind {
                            Identifier(r) => Type::List(Box::new(match r.as_str() {
                                "Str" => Type::Str,
                                "Num" => Type::Num,
                                "Bool" => Type::Bool,
                                l => {
                                    let Some(a) = self.pctx.types.get(l) else {
                                        return Err(format!("Couldn't find type {l}"));
                                    };
                                    Type::Custom(a.clone())
                                }
                            })),
                            _ => Type::Nil,
                        };
                        self.advance();
                        self.consume(TokenKind::RBrack, "Expected ] after type for list type")?;
                        ret
                    }
                    l => return Err(format!("Expected valid type, found {l}")),
                };

                fields.insert(field, act_typ);
                self.advance();
                let _ = self.consume(Comma, "msg");
            }

            self.pctx.types.insert(obj_name, fields);

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
                    _ => Type::Nil,
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
            // Store the function's type signature for strong typing on calls
            self.pctx.var_types.insert(
                fun_name.clone(),
                Type::Function(params.clone(), Box::new(fn_ret_type.clone())),
            );
            Ok(Instruction::FunctionDef {
                body: vec![block],
                name: fun_name,
                params: new_params,
                return_type: fn_ret_type,
            })
        } else if self.match_kind(TokenKind::If) {
            // Parse the primary `if`
            let condition = self.expression()?;
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
            Ok(Instruction::If {
                condition,
                then: vec![then_block_stmt],
                elses: else_node,
            })
        } else if self.match_kind(TokenKind::While) {
            // Parse while loop condition
            let expr = self.expression()?;
            // Static type checking: ensure condition is boolean
            let cond_type = get_type_of_expr(&expr, &self.pctx)?;
            if cond_type != Type::Bool {
                return Err(format!(
                    "Condition in 'while' statement must be a boolean, found {:?}",
                    cond_type,
                ));
            }
            // Parse the loop body (a statement, e.g., a block)
            let body = self.parse_statement()?;
            // Generate a function for the while loop
            Ok(Instruction::While {
                body: vec![body],
                condition: expr,
            })
        } else if self.match_kind(TokenKind::Let) {
            let var_name = if let TokenKind::Identifier(n) = self.peek().kind.clone() {
                self.advance();
                n
            } else {
                return Err("Expected a variable name after 'var'".into());
            };
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
                    get_type_of_expr(first, &self.pctx)?
                } else {
                    Type::Nil
                };
                self.pctx
                    .var_types
                    .insert(name.clone(), Type::List(Box::new(inner_type)));
            }
            // Static type checking: infer expression type and enforce consistency
            let expr_type = get_type_of_expr(&expr, &self.pctx)?;
            if let Some(existing) = self.pctx.var_types.get(&var_name) {
                if *existing != expr_type {
                    return Err(format!(
                        "Cannot redeclare variable '{}' with different type. Previous: {:?}, New: {:?}",
                        var_name, existing, expr_type,
                    ));
                }
            } else {
                self.pctx
                    .var_types
                    .insert(var_name.clone(), expr_type.clone());
            }
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Let {
                name: var_name,
                value: expr,
                type_hint: expr_type,
            })
        } else if matches!(self.peek().kind, TokenKind::Identifier(_))
            && self
                .tokens
                .get(self.current + 1)
                .map(|t| matches!(t.kind, TokenKind::Equal))
                .unwrap_or(false)
        {
            // Assignment statement: <name> = <expr>;
            let name = if let TokenKind::Identifier(n) = self.peek().kind.clone() {
                n
            } else {
                unreachable!();
            };
            self.advance(); // consume identifier
            self.advance(); // consume '='
            let expr = self.expression()?;
            // Static type checking
            let expr_type = get_type_of_expr(&expr, &self.pctx)?;
            if let Some(existing) = self.pctx.var_types.get(&name) {
                if *existing != expr_type && *existing != Type::Nil {
                    return Err(format!(
                        "Cannot assign to variable '{}' with different type. Previous: {:?}, New: {:?}",
                        name, existing, expr_type,
                    ));
                }
            } else {
                return Err(format!("Variable '{}' used before declaration", name));
            }
            if let Some(existing) = self.pctx.var_types.get(&name) {
                if *existing == Type::Nil {
                    self.pctx.var_types.insert(name.clone(), expr_type.clone());
                }
            }
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Assign(name, expr, Some(expr_type)))
        } else {
            // expression statement
            let expr: Expr = self.expression()?;
            let expr_type = get_type_of_expr(&expr, &self.pctx)?;
            if !self.inside_maybe {
                if let Type::Option(_) = expr_type {
                    return Err(
                        "Cannot use a value that might be nil outside of a `maybe` block.".into(),
                    );
                }
            }
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Return(expr))
        }
    }

    // ───── recursive-descent grammar ─────
    fn expression(&mut self) -> Result<Expr, String> {
        self.equality()
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
        self.primary()
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
            return Ok(Expr::Literal(Value::Num(n)));
        } else if let TokenKind::Str(o) = &pekd.kind {
            self.advance();
            return Ok(Expr::Literal(Value::Str(o.into())));
        } else if let TokenKind::Identifier(i) = &pekd.kind {
            self.advance();

            if i.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                && self.match_kind(TokenKind::LBrace)
            {
                let mut vals = HashMap::new();
                while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
                    let Identifier(key) = self.peek().kind else {
                        return Err(format!("Expected identifier, found {}", self.peek().kind));
                    };
                    self.advance();
                    self.consume(Colon, "Expected ':' after field name")?;
                    let expr = self.expression()?;
                    if !self.match_any(&[TokenKind::Comma, TokenKind::RBrace]) {
                        return Err(format!(
                            "Expected ',' or '}}' after field declaration, found {}",
                            self.peek().kind
                        ));
                    }
                    vals.insert(key, expr);
                }
                self.consume(TokenKind::RBrace, "Expected '}' after object literal")?;
                if let Some(r) = self.pctx.types.get(i) {
                    let mut all_fields_present = true;
                    for (name, typ) in r.iter() {
                        if let Some(r_val) = vals.get(name) {
                            let real_type = get_type_of_expr(r_val, &self.pctx)?;
                            if real_type != *typ {
                                return Err(format!(
                                    "Expected {} to be type {:?}, got {:?}",
                                    name, typ, real_type
                                ));
                            }
                        } else {
                            all_fields_present = false;
                            break;
                        }
                    }
                    if !all_fields_present {
                        return Err(format!("{} object requires more fields", i));
                    }
                }
                return Ok(Expr::Object(i.clone(), vals));
            }
            // start with a variable reference
            let mut expr = Expr::Variable(i.clone());
            // handle chained field access: foo.bar.baz
            while self.match_kind(TokenKind::Dot) {
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
            }
            if self.match_kind(TokenKind::LBrack) {
                let indexpr = self.expression()?;
                self.consume(RBrack, "Expected ']' after list index")?;
                return Ok(Expr::Index(Box::new(expr), Box::new(indexpr)));
            }

            if self.match_kind(TokenKind::LParen) {
                let mut args = Vec::new();
                while !self.check(&TokenKind::RParen) {
                    args.push(self.expression()?);
                    if !self.match_kind(TokenKind::Comma) {
                        break;
                    }
                }
                self.consume(TokenKind::RParen, "Expected ')' after arguments.")?;
                if let Some(Type::Function(f, _)) = self.pctx.var_types.get(i).cloned() {
                    if f.len() != args.len() {
                        return Err(format!(
                            "Function parameters incorrect, expected {} found {}",
                            f.len(),
                            args.len(),
                        ));
                    }
                }
                for arg in &args {
                    let ty = get_type_of_expr(arg, &self.pctx)?;
                    if let Some(Type::Function(f, _)) = self.pctx.var_types.get(i).cloned() {
                        for (_, t) in f {
                            let te = match t.as_str() {
                                "Str" => Type::Str,
                                "Num" => Type::Num,
                                "Bool" => Type::Bool,
                                _ => Type::Nil,
                            };
                            if te != ty {
                                return Err(format!(
                                    "Function parameters incorrect, expected {} found {:?}",
                                    t, ty,
                                ));
                            }
                        }
                    }
                }
                expr = Expr::Call(Box::new(expr), args);
            }
            return Ok(expr);
        }

        if self.match_kind(TokenKind::LParen) {
            // parse grouped expression
            let mut expr = self.expression()?;
            self.consume(TokenKind::RParen, "Expect ')' after expression.")?;
            // allow property access, indexing, and calls on grouped expressions
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
                    self.consume(TokenKind::RParen, "Expected ')' after arguments.")?;
                    expr = Expr::Call(Box::new(expr), args);
                } else {
                    break;
                }
            }
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
            // allow property access on lists, e.g., list.len
            let mut expr = Expr::List(items);
            while self.match_kind(TokenKind::Dot) {
                if let TokenKind::Identifier(name) = &self.peek().kind {
                    self.advance();
                    expr = Expr::Get(Box::new(expr), name.clone());
                } else {
                    return Err(format!(
                        "Expected property name after '.', found {}",
                        self.peek().kind
                    ));
                }
            }
            if self.match_kind(TokenKind::LParen) {
                let mut args = Vec::new();
                while !self.check(&TokenKind::RParen) {
                    args.push(self.expression()?);
                    if !self.match_kind(TokenKind::Comma) {
                        break;
                    }
                }
                self.consume(TokenKind::RParen, "Expected ')' after arguments.")?;
                expr = Expr::Call(Box::new(expr), args);
            }
            return Ok(expr);
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
            let wow = Token {
                kind: Eof,
                value: "".into(),
                line: self.previous().line,
            };
            wow
        }
    }
    fn previous(&self) -> &Token {
        &self.tokens[self.current - 1]
    }
}

impl Display for TokenKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::LParen => "LEFT_PAREN",
            Self::RParen => "RIGHT_PAREN",
            Self::LBrace => "LEFT_BRACE",
            Self::RBrace => "RIGHT_BRACE",
            Self::LBrack => "LEFT_BRACK",
            Self::RBrack => "RIGHT_BRACK",
            Self::Star => "STAR",
            Self::Dot => "DOT",
            Self::Comma => "COMMA",
            Self::Plus => "PLUS",
            Self::Minus => "MINUS",
            Self::Colon => "COLON",
            Self::Semicolon => "SEMICOLON",
            Self::Equal => "EQUAL",
            Self::EqualEqual => "EQUAL_EQUAL",
            Self::Bang => "BANG",
            Self::BangEqual => "BANG_EQUAL",
            Self::Less => "LESS",
            Self::LessEqual => "LESS_EQUAL",
            Self::Greater => "GREATER",
            Self::GreaterEqual => "GREATER_EQUAL",
            Self::Slash => "SLASH",
            Self::Str(_) => "STRING",
            Self::Num(_) => "NUMBER",
            Self::Identifier(_) => "IDENTIFIER",
            Self::And => "AND",
            Self::Object => "OBJECT",
            Self::Maybe => "MAYBE",
            Self::Else => "ELSE",
            Self::False => "FALSE",
            Self::For => "FOR",
            Self::Fun => "FUN",
            Self::If => "IF",
            Self::Nil => "NIL",
            Self::Or => "OR",
            Self::Print => "PRINT",
            Self::Reprint => "REPRINT",
            Self::Return => "RETURN",
            Self::Super => "SUPER",
            Self::This => "THIS",
            Self::True => "TRUE",
            Self::Let => "LET",
            Self::While => "WHILE",
            Self::Eof => "EOF",
            Self::Error(line, error) => &format!("[line {line}] Error: {error}"),
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
        "maybe" => Maybe,
        "else" => Else,
        "false" => False,
        "for" => For,
        "fun" => Fun,
        "if" => If,
        "nil" => Nil,
        "or" => Or,
        "print" => Print,
        "reprint" => Reprint,
        "return" => Return,
        "super" => Super,
        "this" => This,
        "true" => True,
        "let" => Let,
        "while" => While,
        _ => Identifier(val),
    }
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn main() {
    let args: Vec<std::string::String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} tokenize <filename>", args[0]);
        return;
    }

    let command = &args[1];
    let filename = &args[2];

    match command.as_str() {
        "run" => {
            let file_contents = fs::read_to_string(filename).unwrap_or_else(|_| {
                eprintln!("Failed to read file {}", filename);
                std::string::String::new()
            });
            let tokens = tokenize(file_contents.chars().collect());
            // Lexical error check
            if tokens.iter().any(|t| matches!(t.kind, Error(_, _))) {
                for t in tokens {
                    if let Error(_, _) = t.kind {
                        t.print();
                    }
                }
                std::process::exit(65);
            }
            let mut parser = Parser::new(tokens);
            match parser.parse_program() {
                Ok(p) => {
                    let context = context::Context::create();
                    let module = context.create_module("sum");
                    let execution_engine = module
                        .create_jit_execution_engine(OptimizationLevel::Aggressive)
                        .unwrap();
                    let codegen = Compiler {
                        context: &context,
                        module,
                        builder: context.create_builder(),
                        execution_engine,
                        instructions: p,
                        vars: RefCell::new(HashMap::new()),
                        var_types: RefCell::new(HashMap::new()),
                        pctx: RefCell::new(parser.pctx),
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

                    unsafe {
                        println!("Result: {}", sum.call());
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(65);
                }
            }
        }
        _ => {
            eprintln!("Unknown command: {}", command);
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
    pctx: RefCell<PreCtx>,
}
use inkwell::FloatPredicate;
use inkwell::IntPredicate;
use inkwell::types::BasicMetadataTypeEnum;
impl<'ctx> Compiler<'ctx> {
    /// Expose C rand() → i32
    fn get_or_create_rand(&self) -> FunctionValue<'ctx> {
        self.module.get_function("rand").unwrap_or_else(|| {
            let fn_type = self.context.i32_type().fn_type(&[], false);
            self.module.add_function("rand", fn_type, None)
        })
    }

    fn run_code(&self) -> Option<JitFunction<'_, SumFunc>> {
        let f64_type = self.context.f64_type();
        // Match SumFunc signature: three u64 parameters
        let fn_type = f64_type.fn_type(&[], false);
        let main_fn = self.module.add_function("main", fn_type, None);
        // Entry block and position builder
        let entry_bb = self.context.append_basic_block(main_fn, "entry");
        self.builder.position_at_end(entry_bb);
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

        // Ensure C library functions are resolved at runtime to prevent segfaults
        let strcmp_fn = self.get_or_create_strcmp();
        self.execution_engine
            .add_global_mapping(&strcmp_fn, strcmp as usize);
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

        // Retrieve the JIT'd function
        unsafe { self.execution_engine.get_function("main").ok() }
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
                    panic!()
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
                for i in b {
                    self.compile_instruction(function, i)?;
                }
                Ok(())
            }
            Instruction::Let { name, value, .. } => {
                let init_val = self.compile_expr(value)?;
                let elem_type = init_val.get_type();

                // Hoist allocas to the entry block to avoid stack overflow in loops.
                let entry = function.get_first_basic_block().unwrap();
                let temp_builder = self.context.create_builder();
                match entry.get_first_instruction() {
                    Some(inst) => temp_builder.position_before(&inst),
                    None => temp_builder.position_at_end(entry),
                }

                let ptr = temp_builder.build_alloca(elem_type, name).unwrap();
                self.builder.build_store(ptr, init_val)?;
                self.vars.borrow_mut().insert(name.clone(), ptr);
                self.var_types
                    .borrow_mut()
                    .insert(name.clone(), elem_type.as_basic_type_enum());
                Ok(())
            }
            Instruction::For {
                init,
                condition,
                step,
                body,
            } => {
                let cond_bb = self.context.append_basic_block(function, "for.cond");
                let body_bb = self.context.append_basic_block(function, "for.body");
                let step_bb = self.context.append_basic_block(function, "for.step");
                let cont_bb = self.context.append_basic_block(function, "for.cont");

                // init
                self.compile_instruction(function, init)?;
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(cond_bb)?;
                }

                // condition
                self.builder.position_at_end(cond_bb);
                let cond_val = self.compile_expr(condition)?.into_int_value();
                self.builder
                    .build_conditional_branch(cond_val, body_bb, cont_bb)?;

                // body
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

                // step
                self.builder.position_at_end(step_bb);
                self.compile_instruction(function, step)?;
                if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    self.builder.build_unconditional_branch(cond_bb)?;
                }

                // continuation
                self.builder.position_at_end(cont_bb);
                Ok(())
            }
            Instruction::Assign(name, new_val, _typ) => {
                // Check if this is a string concatenation assignment (var = var + something)
                if let Expr::Binary(left_expr, BinOp::Plus, right_expr) = new_val {
                    if let Expr::Variable(var_name) = left_expr.as_ref() {
                        if var_name == name {
                            // This is var = var + something, use optimized append
                            return self.compile_safe_string_append(name, right_expr);
                        }
                    }
                }

                // Regular assignment
                let new_c = self.compile_expr(new_val)?;
                let binding = self.vars.borrow();
                let ptr = binding
                    .get(name)
                    .unwrap_or_else(|| panic!("Variable not found: {name}"));
                self.builder.build_store(*ptr, new_c)?;
                Ok(())
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
                    _ => unreachable!(),
                }
                Ok(())
            }
            Instruction::FunctionDef {
                name,
                params,
                return_type,
                body,
            } => {
                // Build LLVM function signature based on parameter and return types
                // Map QuickLang types to LLVM types
                let llvm_ret_type = match return_type {
                    Type::Num => self.context.f64_type().as_basic_type_enum(),
                    Type::Bool => self.context.bool_type().as_basic_type_enum(),
                    Type::Str => self
                        .context
                        .ptr_type(AddressSpace::default())
                        .as_basic_type_enum(),
                    Type::Nil => BasicTypeEnum::FloatType(self.context.f64_type()),
                    other => unimplemented!("Return type {:?} not supported", other),
                };

                let param_llvm_types: Vec<BasicTypeEnum> = params
                    .iter()
                    .map(|(_, ty)| match ty {
                        Type::Num => self.context.f64_type().as_basic_type_enum(),
                        Type::Bool => self.context.bool_type().as_basic_type_enum(),
                        Type::Str => self
                            .context
                            .ptr_type(AddressSpace::default())
                            .as_basic_type_enum(),
                        other => unimplemented!("Parameter type {:?} not supported", other),
                    })
                    .collect();

                let param_metadata_types: Vec<BasicMetadataTypeEnum> =
                    param_llvm_types.iter().map(|&t| t.into()).collect();

                // Create the function type (void vs non-void)
                // Build the LLVM function type based on the return type variant
                let fn_type = match llvm_ret_type {
                    BasicTypeEnum::IntType(int_ty) => {
                        int_ty.fn_type(param_metadata_types.as_slice(), false)
                    }
                    BasicTypeEnum::PointerType(ptr_ty) => {
                        ptr_ty.fn_type(param_metadata_types.as_slice(), false)
                    }
                    BasicTypeEnum::FloatType(float_ty) => {
                        float_ty.fn_type(param_metadata_types.as_slice(), false)
                    }
                    BasicTypeEnum::ArrayType(array_ty) => {
                        array_ty.fn_type(param_metadata_types.as_slice(), false)
                    }
                    BasicTypeEnum::ScalableVectorType(scvec_ty) => {
                        scvec_ty.fn_type(param_metadata_types.as_slice(), false)
                    }
                    BasicTypeEnum::VectorType(vec_ty) => {
                        vec_ty.fn_type(param_metadata_types.as_slice(), false)
                    }
                    BasicTypeEnum::StructType(struct_ty) => {
                        struct_ty.fn_type(param_metadata_types.as_slice(), false)
                    }
                };

                // Add the function to the module
                let function = self.module.add_function(name, fn_type, None);

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
                    let param_elem_type = match typ {
                        Type::Num => self.context.f64_type().as_basic_type_enum(),
                        Type::Bool => self.context.bool_type().as_basic_type_enum(),
                        Type::Str => self
                            .context
                            .ptr_type(AddressSpace::default())
                            .as_basic_type_enum(),
                        Type::Nil => self.context.f64_type().as_basic_type_enum(),
                        other => unimplemented!("Parameter type {:?} not supported", other),
                    };
                    self.var_types
                        .borrow_mut()
                        .insert(param_name.clone(), param_elem_type);
                }

                // Compile the body of the function
                for instr in body {
                    self.compile_instruction(function, instr)?;
                }

                // Ensure the function has a return instruction
                if matches!(return_type, Type::Nil) {
                    if self
                        .builder
                        .get_insert_block()
                        .unwrap()
                        .get_terminator()
                        .is_none()
                    {
                        let zero = self.context.f64_type().const_float(0.0);
                        self.builder.build_return(Some(&zero))?;
                    }
                } else if self
                    .builder
                    .get_insert_block()
                    .unwrap()
                    .get_terminator()
                    .is_none()
                {
                    // Default return zero for numeric functions
                    let zero = self.context.f64_type().const_float(0.0);
                    self.builder.build_return(Some(&zero))?;
                }
                Ok(())
            }
            Instruction::Maybe(maybe, block, otherwise) => {
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
                    _ => panic!("Unsupported type in maybe"),
                }
                .unwrap();
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
            let i8ptr = self.context.ptr_type(AddressSpace::default());
            let fn_type = self.context.i32_type().fn_type(&[i8ptr.into()], true);
            self.module.add_function("free", fn_type, None)
        }
    }
    fn compile_expr(&self, expr: &Expr) -> Result<BasicValueEnum<'ctx>, BuilderError> {
        match expr {
            Expr::Variable(var_name) => {
                let ptr = *self.vars.borrow().get(var_name).unwrap();
                let ty = *self.var_types.borrow().get(var_name).unwrap();
                let loaded = self.builder.build_load(ty, ptr, var_name)?;
                Ok(loaded)
            }
            // Handle io.random() as a call: io.random() → random integer < 1_000_000
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
                Ok(gs.as_pointer_value().as_basic_value_enum())
            }
            Expr::Binary(left, op, right) => {
                // Compile both sides
                let lval = self.compile_expr(left)?;
                let rval = self.compile_expr(right)?;
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
                    _ => panic!(
                        "Type mismatch in binary expression: {:?} vs {:?}",
                        lval, rval
                    ),
                }
            }

            Expr::Literal(Value::Str(s)) => {
                // 1) stick a C
                // -string into the module
                let gs = self
                    .builder
                    .build_global_string_ptr(&format!("{}\0", s), "str_literal")
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
                let type_fields = binding.types.get(type_name).unwrap();
                for (idx, field_name) in type_fields.keys().enumerate() {
                    let expr = &fields[field_name];
                    let val = self.compile_expr(expr)?;
                    let idx_const = self.context.i64_type().const_int(idx as u64, false);
                    let field_ptr = unsafe {
                        self.builder
                            .build_in_bounds_gep(
                                slot_ty,
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
                // Compile the base object pointer
                let base_val = self.compile_expr(obj_expr)?;
                let obj_ptr = base_val.into_pointer_value();
                // Determine the object's declared type by looking up the variable's static type
                let var_name = if let Expr::Variable(name) = &**obj_expr {
                    name
                } else {
                    panic!("Property access on non-variable object");
                };
                // Find the matching custom type definition
                let binding = self.pctx.borrow();
                let custom_type = match &binding.var_types[var_name] {
                    Type::Custom(map) => map,
                    _ => panic!("Variable {var_name} is not a custom object"),
                };
                let type_name = self
                    .pctx
                    .borrow()
                    .types
                    .iter()
                    .find(|(_, def)| def == &custom_type)
                    .map(|(k, _)| k.clone())
                    .unwrap();
                let field_defs = &self.pctx.borrow().types[&type_name];
                // Find the index of this property
                let index = field_defs.keys().position(|k| k == prop).unwrap() as u64;
                let idx_const = self.context.i64_type().const_int(index, false);
                let slot_ty = self.context.ptr_type(AddressSpace::default());
                // Compute address and load
                // Compute the address of the field
                let field_ptr = unsafe {
                    self.builder
                        .build_in_bounds_gep(
                            slot_ty,
                            obj_ptr,
                            &[idx_const],
                            &format!("load_{}", prop),
                        )
                        .unwrap()
                };
                // Determine the field’s QuickLang type
                let binding = self.pctx.borrow();
                let field_ty = binding.types[&type_name][prop].clone();
                // Pick the right LLVM type
                let elem_basic = match field_ty {
                    Type::Str => self
                        .context
                        .ptr_type(AddressSpace::default())
                        .as_basic_type_enum(),
                    Type::Num => self.context.f64_type().as_basic_type_enum(),
                    Type::Bool => self.context.bool_type().as_basic_type_enum(),
                    other => panic!("Unsupported field type {:?}", other),
                };
                // Load with the correct type
                let loaded = self
                    .builder
                    .build_load(elem_basic, field_ptr, prop)
                    .unwrap();
                Ok(loaded)
            }
            Expr::Call(callee, args) => {
                // Compile the function or method being called
                match &**callee {
                    // 1) Direct function call: foo(arg1, arg2, ...)
                    Expr::Variable(name) => {
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
                    Expr::Get(obj, method) if method == "str" => {
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

                    // 2) Method call `.len()` on a pointer value (string or later list)
                    Expr::Get(obj, method) if method == "len" => {
                        let obj_val = self.compile_expr(obj)?;
                        // Get the original type of the object from pctx
                        let obj_type = get_type_of_expr(obj, &self.pctx.borrow())
                            .unwrap_or_else(|e| panic!("Type error: {}", e));

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

                    _ => {
                        panic!("Unsupported call expression: {:?}", callee);
                    }
                }
            }
            Expr::List(items) => {
                let count = items.len() as u64;
                let f64_ty = self.context.f64_type();
                let f64_ptr_ty = self.context.ptr_type(AddressSpace::default());

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
                let buf_ptr =
                    self.builder
                        .build_pointer_cast(raw_ptr, f64_ptr_ty, "list_buf_ptr")?;

                // Store length at index 0
                let len_val = f64_ty.const_float(count as f64);
                let len_ptr = unsafe {
                    self.builder.build_in_bounds_gep(
                        f64_ptr_ty,
                        buf_ptr,
                        &[self.context.i64_type().const_int(0, false)],
                        "len_ptr",
                    )?
                };
                let _ = self.builder.build_store(len_ptr, len_val);

                // Store each element starting from index 1
                for (idx, item) in items.iter().enumerate() {
                    let elem_val = self.compile_expr(item)?.into_float_value();
                    let idx_val = self.context.i64_type().const_int((idx + 1) as u64, false);
                    let gep = unsafe {
                        self.builder.build_in_bounds_gep(
                            f64_ptr_ty,
                            buf_ptr,
                            &[idx_val],
                            "elem_ptr",
                        )?
                    };
                    let _ = self.builder.build_store(gep, elem_val);
                }

                Ok(buf_ptr.as_basic_value_enum())
            }
            Expr::Index(list, indexed_by) => {
                let list_lit = self.compile_expr(list)?;
                let index_lit = self.compile_expr(indexed_by)?;
                // get the raw list pointer and index integer
                let list_ptr = match list_lit {
                    BasicValueEnum::PointerValue(p) => p,
                    _ => panic!("Index on non-list pointer: {:?}", list_lit),
                };
                let idx = match index_lit {
                    BasicValueEnum::IntValue(i) => i,
                    _ => panic!("List index must be integer: {:?}", index_lit),
                };
                // skip the length slot at index 0
                let one = self.context.i64_type().const_int(1, false);
                let idx1 = self.builder.build_int_add(idx, one, "idx_plus1")?;
                // compute element pointer and load
                let elem_ptr = unsafe {
                    self.builder
                        .build_in_bounds_gep(
                            self.context.ptr_type(AddressSpace::default()),
                            list_ptr,
                            &[idx1],
                            "list_index",
                        )
                        .unwrap()
                };
                let loaded = self
                    .builder
                    .build_load(self.context.f64_type(), elem_ptr, "load_elem")
                    .unwrap();
                Ok(loaded)
            }

            _ => panic!("Unsupported expression in compile_expr: {:?}", expr),
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

    fn jit_compile_sum(&self) -> Option<JitFunction<'_, SumFunc>> {
        let i64_type = self.context.i64_type();
        let fn_type = i64_type.fn_type(&[i64_type.into(), i64_type.into(), i64_type.into()], false);
        let function = self.module.add_function("sum", fn_type, None);
        let basic_block = self.context.append_basic_block(function, "entry");

        self.builder.position_at_end(basic_block);

        let x = function.get_nth_param(0)?.into_int_value();
        let y = function.get_nth_param(1)?.into_int_value();
        let z = function.get_nth_param(2)?.into_int_value();

        let sum = self.builder.build_int_add(x, y, "sum").unwrap();
        let sum = self.builder.build_int_add(sum, z, "sum").unwrap();

        self.builder.build_return(Some(&sum)).unwrap();

        unsafe { self.execution_engine.get_function("sum").ok() }
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
    let mut in_string: Option<std::string::String> = None;

    let mut tokens = vec![];
    let mut line = 1;
    let mut index = 0;

    while index < chars.len() {
        let current_char = chars[index];

        // Handle comments
        if is_commented {
            if current_char == '\n' {
                is_commented = false;
                line += 1;
            }
            index += 1;
            continue;
        }

        // Handle strings
        if current_char == '"' {
            if in_string.is_none() {
                in_string = Some("".to_string());
            } else {
                tokens.push(Token {
                    value: in_string.clone().unwrap(),
                    kind: Str(in_string.clone().unwrap()),
                    line,
                });
                in_string = None;
            }
            index += 1;
            continue;
        } else if let Some(ref mut s) = in_string {
            s.push(current_char);
            index += 1;
            continue;
        }

        // Handle newlines
        if current_char == '\n' {
            line += 1;
            index += 1;
            continue;
        }
        // Skip whitespace
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

    if in_string.is_some() {
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
fn get_type_of_expr(expr: &Expr, ctx: &PreCtx) -> Result<Type, String> {
    match expr {
        Expr::Variable(v) => match ctx.var_types.get(v) {
            Some(t) => Ok(t.clone()),
            None => {
                eprintln!("Variable \"{}\" not found", v);
                std::process::exit(70);
            }
        },
        Expr::Index(list, _) => get_type_of_expr(list, ctx),
        Expr::Object(_name, o) => {
            let mut fields = HashMap::new();
            for (name, expr) in o.iter() {
                let field_type = get_type_of_expr(expr, ctx)?;
                fields.insert(name.clone(), field_type);
            }
            Ok(Type::Custom(fields))
        }
        Expr::Literal(tk) => match tk {
            Value::Num(_) => Ok(Type::Num),
            Value::Str(_) => Ok(Type::Str),
            Value::Bool(_) => Ok(Type::Bool),
            Value::Nil => Ok(Type::Nil),
            _ => Err("Unsupported literal type".into()),
        },
        Expr::List(l) => Ok(Type::List(if let Some(r) = l.first() {
            Box::new(get_type_of_expr(r, ctx)?)
        } else {
            Box::new(Type::Nil)
        })),
        Expr::Unary(_, e) => get_type_of_expr(e, ctx),
        Expr::Grouping(e) => get_type_of_expr(e, ctx),
        Expr::Binary(l, op, r) => {
            let lt = get_type_of_expr(l, ctx)?;
            let rt = get_type_of_expr(r, ctx)?;
            match op {
                BinOp::Plus => match (&lt, &rt) {
                    (Type::Num, Type::Num) => Ok(Type::Num),
                    (Type::Str, Type::Str) => Ok(Type::Str),
                    _ => Err("Operands of '+' must be both numbers or both strings".into()),
                },
                BinOp::Minus | BinOp::Mult | BinOp::Div => {
                    if lt == Type::Num && rt == Type::Num {
                        Ok(Type::Num)
                    } else {
                        Err(format!("Operator {:?} requires two numbers", op))
                    }
                }
                BinOp::EqEq | BinOp::NotEq => Ok(Type::Bool),
                BinOp::Greater | BinOp::Less | BinOp::GreaterEqual | BinOp::LessEqual => {
                    if lt == Type::Num && rt == Type::Num {
                        Ok(Type::Bool)
                    } else {
                        Err(format!("Operator {:?} requires two numbers", op))
                    }
                }
            }
        }

        Expr::Get(obj, prop) => {
            // Type-checking for field access
            let obj_type = get_type_of_expr(obj, ctx)?;
            match obj_type {
                Type::List(_) => {
                    if prop == "len" {
                        Ok(Type::Function(vec![], Box::new(Type::Num)))
                    } else {
                        Err(format!("Property '{}' not found on list type", prop))
                    }
                }
                Type::Io => {
                    // Special-case io properties

                    match prop.as_str() {
                        "random" => Ok(Type::Function(vec![], Box::new(Type::Num))),
                        "input" => Ok(Type::Function(
                            vec![("prompt".to_string(), "Str".to_string())],
                            Box::new(Type::Str),
                        )),
                        "route" => Ok(Type::Function(
                            vec![
                                ("method".to_string(), "Str".to_string()),
                                ("route".to_string(), "Str".to_string()),
                                ("func".to_string(), "Function".to_string()),
                            ],
                            Box::new(Type::Nil),
                        )),
                        "listen" => Ok(Type::Function(
                            vec![("port".to_string(), "Num".to_string())],
                            Box::new(Type::Nil),
                        )),
                        "read" => Ok(Type::Function(
                            vec![("path".to_string(), "Str".to_string())],
                            Box::new(Type::Str),
                        )),
                        "write" => Ok(Type::Function(
                            vec![
                                ("path".to_string(), "Str".to_string()),
                                ("content".to_string(), "Str".to_string()),
                            ],
                            Box::new(Type::Nil),
                        )),
                        other => Err(format!("Unknown property '{}' on io", other)),
                    }
                }
                Type::Num => match prop.as_str() {
                    "str" => Ok(Type::Function(vec![], Box::new(Type::Str))),
                    other => Err(format!("Unknown property '{}' on type Num", other)),
                },
                Type::Custom(fields) => {
                    // Look up property in custom type
                    if let Some(t) = fields.get(prop) {
                        Ok(t.clone())
                    } else {
                        Err(format!(
                            "Property '{}' not found on type {:?}",
                            prop, fields,
                        ))
                    }
                }
                other => Err(format!(
                    "Cannot access property '{}' on type {:?}",
                    prop, other,
                )),
            }
        }
        Expr::Block(_) => Ok(Type::Nil),
        Expr::Call(callee, args) => {
            // Special-case: io.random() always returns a number
            if let Expr::Get(inner, prop) = &**callee {
                if let Expr::Variable(obj) = &**inner {
                    if obj == "io" && prop == "random" {
                        if args.is_empty() {
                            return Ok(Type::Num);
                        } else {
                            return Err(format!(
                                "io.random() expects no arguments, got {}",
                                args.len(),
                            ));
                        }
                    }
                }
            }
            // Existing function call type-checking
            let callee_type = get_type_of_expr(callee, ctx)?;
            if let Type::Function(params, ret_type) = callee_type {
                if args.len() != params.len() {
                    return Err(format!(
                        "Expected {} arguments but got {}",
                        params.len(),
                        args.len(),
                    ));
                }
                // verify each arg’s inferred type against the declared parameter type
                for (i, (_, param_tstr)) in params.iter().enumerate() {
                    let arg_t = get_type_of_expr(&args[i], ctx)?;
                    if param_tstr == "Function" {
                        // Accept any function value
                        if let Type::Function(_, _) = arg_t {
                            // OK
                        } else {
                            return Err(format!(
                                "Parameter #{} type mismatch: expected a function, got {:?}",
                                i, arg_t,
                            ));
                        }
                    } else {
                        let expected = match param_tstr.as_str() {
                            "Num" => Type::Num,
                            "Str" => Type::Str,
                            "Bool" => Type::Bool,
                            _ => Type::Nil,
                        };
                        if expected != arg_t {
                            return Err(format!(
                                "Parameter #{} type mismatch: expected {:?}, got {:?}",
                                i, expected, arg_t,
                            ));
                        }
                    }
                }
                Ok(*ret_type)
            } else {
                Err(format!("Can only call functions, found {:?}", callee_type))
            }
        }
    }
}
