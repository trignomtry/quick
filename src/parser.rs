use crate::*;

pub struct Parser {
    tokens: Vec<Token>,
    current: usize, // index into `tokens`
    pub pctx: PreCtx,
    current_return_type: Option<Type>,
    saw_non_nil_return: bool,
    saw_nil_return: bool,
    saw_never_return: bool,
    is_global: bool,
    loop_depth: usize,
    generic_scopes: Vec<HashSet<String>>,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            current: 0,
            pctx: PreCtx::default(),
            current_return_type: None,
            saw_non_nil_return: false,
            saw_nil_return: false,
            saw_never_return: false,
            is_global: true,
            loop_depth: 0,
            generic_scopes: Vec::new(),
        }
    }

    fn push_generic_scope(&mut self, params: &[String]) {
        let mut scope = HashSet::new();
        for param in params {
            scope.insert(param.clone());
        }
        self.generic_scopes.push(scope);
    }

    fn pop_generic_scope(&mut self) {
        self.generic_scopes.pop();
    }

    fn is_generic_param(&self, name: &str) -> bool {
        for scope in self.generic_scopes.iter().rev() {
            if scope.contains(name) {
                return true;
            }
        }
        false
    }

    fn enum_variants_for_type(&self, ty: &Type) -> Option<Vec<EnumVariant>> {
        match ty {
            Type::Custom(Custype::Enum(variants)) => Some(variants.clone()),
            Type::Option(inner) => Some(vec![
                EnumVariant {
                    name: "Some".to_string(),
                    payload: vec![(*inner.clone())],
                },
                EnumVariant {
                    name: "None".to_string(),
                    payload: vec![],
                },
            ]),
            Type::Result(ok, err) => Some(vec![
                EnumVariant {
                    name: "Ok".to_string(),
                    payload: vec![(*ok.clone())],
                },
                EnumVariant {
                    name: "Err".to_string(),
                    payload: vec![(*err.clone())],
                },
            ]),
            _ => None,
        }
    }

    fn match_builtin_variant(
        &self,
        ty: &Type,
        pattern: &Expr,
    ) -> Option<(String, String, Vec<Expr>)> {
        match (ty, pattern) {
            (Type::Option(_), Expr::OptionSome(value)) => Some((
                "Option".to_string(),
                "Some".to_string(),
                vec![(*value.clone())],
            )),
            (Type::Option(_), Expr::OptionNone) => {
                Some(("Option".to_string(), "None".to_string(), Vec::new()))
            }
            (Type::Result(_, _), Expr::ResultOk(value)) => Some((
                "Result".to_string(),
                "Ok".to_string(),
                vec![(*value.clone())],
            )),
            (Type::Result(_, _), Expr::ResultErr(value)) => Some((
                "Result".to_string(),
                "Err".to_string(),
                vec![(*value.clone())],
            )),
            _ => None,
        }
    }

    fn build_enum_patterns(
        &mut self,
        payload_exprs: &[Expr],
        variant_def: &EnumVariant,
        case_line: usize,
        allow_literals: bool,
    ) -> Result<(Vec<EnumPattern>, Vec<(String, Option<Type>)>), String> {
        let mut binding_names = Vec::new();
        let mut restores = Vec::new();
        let mut patterns = Vec::new();

        for (arg_expr, payload_ty) in payload_exprs.iter().zip(variant_def.payload.iter()) {
            match arg_expr {
                Expr::Variable(binding_name) => {
                    if binding_names.contains(binding_name) {
                        return Err(format!(
                            "Enum pattern binding '{binding_name}' appears more than once"
                        ));
                    }
                    let previous = self
                        .pctx
                        .var_types
                        .insert(binding_name.clone(), payload_ty.clone());
                    restores.push((binding_name.clone(), previous));
                    binding_names.push(binding_name.clone());
                    patterns.push(EnumPattern::Binding(binding_name.clone()));
                }
                Expr::Literal(_) if allow_literals => {
                    let literal_ty = self
                        .pctx
                        .with_line(Some(case_line), || arg_expr.get_type(&self.pctx))?;
                    if &literal_ty != payload_ty {
                        return Err(format!(
                            "Literal pattern for variant '{}' must have type {:?}, found {:?}",
                            variant_def.name, payload_ty, literal_ty
                        ));
                    }
                    patterns.push(EnumPattern::Literal(arg_expr.clone()));
                }
                Expr::Literal(_) => {
                    return Err(
                        "Only variable bindings are currently supported in this match pattern"
                            .to_string(),
                    );
                }
                _ => {
                    return Err(
                        "Enum variant patterns must be variable names or literals".to_string()
                    );
                }
            }
        }

        Ok((patterns, restores))
    }

    // ───── entry point ─────

    pub fn parse_program(&mut self) -> Result<Vec<Instruction>, String> {
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
        while self.match_kind(TokenKind::Semicolon) {}
        // Optional debug hook to trace unexpected brace parsing issues
        if std::env::var("QS_DEBUG_BRACE").is_ok() && self.check(&TokenKind::RBrace) {
            let prev = if self.current > 0 {
                self.tokens.get(self.current - 1)
            } else {
                None
            };
            let (prev_line, prev_val) = if let Some(tok) = prev {
                (tok.line, tok.value.clone())
            } else {
                (0, "".into())
            };
            eprintln!(
                "debug: hit '}}' while expecting a statement at line {} (previous token '{}' on line {})",
                self.peek().line,
                prev_val,
                prev_line
            );
        }
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
            } else if ret_type == Type::Never {
                self.saw_never_return = true;
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
            minfo.generic_types = mod_parser.pctx.generic_types.clone();
            minfo.deserialize_plans = mod_parser.pctx.deserialize_registry.clone();

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
        } else if self.match_kind(TokenKind::LBrace) {
            let was = self.is_global;
            self.is_global = false;
            let debug_brace = std::env::var("QS_DEBUG_BRACE").is_ok();
            if debug_brace {
                eprintln!("debug: enter block starting at line {}", self.previous().line);
            }
            // Static type scope for block: save outer types
            let saved_types = self.pctx.var_types.clone();
            let mut stmts = Vec::new();
            while !self.check(&TokenKind::RBrace) && !self.is_at_end() {
                if debug_brace {
                    eprintln!(
                        "debug: block loop parsing statement starting with {:?} at line {}",
                        self.peek().kind,
                        self.peek().line
                    );
                }
                stmts.push(self.parse_statement()?);
            }
            self.consume(TokenKind::RBrace, "Expected '}' after block")?;
            if debug_brace {
                eprintln!("debug: exit block at line {}", self.previous().line);
            }
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
            let mut generic_params = Vec::new();
            if self.match_kind(TokenKind::Less) {
                loop {
                    let TokenKind::Identifier(param_name) = self.peek().kind.clone() else {
                        return Err(format!(
                            "Expected type parameter name while declaring object '{obj_name}'"
                        ));
                    };
                    self.advance();
                    if generic_params.contains(&param_name) {
                        return Err(format!(
                            "Duplicate type parameter '{param_name}' in object '{obj_name}'"
                        ));
                    }
                    generic_params.push(param_name);
                    if self.match_kind(TokenKind::Greater) {
                        break;
                    }
                    self.consume(
                        TokenKind::Comma,
                        "Expected ',' or '>' after generic parameter",
                    )?;
                }
            }

            self.consume(LBrace, "Expected a { after object name")?;
            self.push_generic_scope(&generic_params);
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
            self.pop_generic_scope();

            if generic_params.is_empty() {
                self.pctx
                    .register_object_descriptor(&obj_name, &[], &fields);
                self.pctx.types.insert(obj_name, Custype::Object(fields));
            } else {
                self.pctx.generic_types.insert(
                    obj_name,
                    GenericTypeTemplate {
                        params: generic_params,
                        body: Custype::Object(fields),
                    },
                );
            }

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
                let mut payload = Vec::new();
                if self.match_kind(TokenKind::LParen) {
                    if self.match_kind(TokenKind::RParen) {
                        // empty payload list
                    } else {
                        loop {
                            let ty = self.parse_type()?;
                            payload.push(ty);
                            if self.match_kind(TokenKind::RParen) {
                                break;
                            }
                            self.consume(
                                TokenKind::Comma,
                                "Expected ',' or ')' while parsing enum variant payload",
                            )?;
                        }
                    }
                }
                self.consume(
                    TokenKind::Comma,
                    format!(
                        "Expected Comma after enum variant, found {}",
                        self.peek().value
                    )
                    .as_str(),
                )?;
                variants.push(EnumVariant {
                    name: variant_name,
                    payload,
                });
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
                let mut handled_enum_pattern = false;

                if let Some((enum_name, variant_name, payload_exprs)) =
                    self.match_builtin_variant(&matching_expr_type, &matching)
                {
                    let enum_variants = self
                        .enum_variants_for_type(&matching_expr_type)
                        .expect("Match expression should describe variants");
                    let Some(variant_def) = enum_variants
                        .iter()
                        .find(|variant| variant.name == variant_name)
                    else {
                        return Err(format!(
                            "Type {:?} does not contain variant '{}'",
                            matching_expr_type, variant_name
                        ));
                    };
                    if variant_def.payload.len() != payload_exprs.len() {
                        return Err(format!(
                            "Variant '{}' expects {} argument(s), found {}",
                            variant_name,
                            variant_def.payload.len(),
                            payload_exprs.len()
                        ));
                    }

                    self.consume(
                        TokenKind::BigArrow,
                        &format!("Expected => in match statement, found {}", self.peek().kind),
                    )?;
                    let (patterns, restores) =
                        self.build_enum_patterns(&payload_exprs, variant_def, case_line, false)?;
                    let body = self.parse_statement()?;

                    for (binding_name, previous) in restores {
                        if let Some(prev_ty) = previous {
                            self.pctx.var_types.insert(binding_name, prev_ty);
                        } else {
                            self.pctx.var_types.remove(&binding_name);
                        }
                    }

                    arms.push(MatchArm::EnumDestructure {
                        enum_name,
                        enum_type: matching_expr_type.clone(),
                        variant: variant_name,
                        patterns,
                        body,
                    });
                    self.match_kind(TokenKind::Comma);
                    handled_enum_pattern = true;
                } else if let Expr::Call(callee, args) = &matching {
                    if let Expr::Get(enum_expr, variant_name) = &**callee {
                        if let Expr::Variable(enum_name) = &**enum_expr {
                            if let Some(enum_variants) =
                                self.enum_variants_for_type(&matching_expr_type)
                            {
                                if let Some(variant_def) = enum_variants
                                    .iter()
                                    .find(|variant| variant.name == *variant_name)
                                {
                                    if variant_def.payload.len() != args.len() {
                                        return Err(format!(
                                            "Variant '{}' expects {} argument(s), found {}",
                                            variant_name,
                                            variant_def.payload.len(),
                                            args.len()
                                        ));
                                    }

                                    self.consume(
                                        TokenKind::BigArrow,
                                        &format!(
                                            "Expected => in match statement, found {}",
                                            self.peek().kind
                                        ),
                                    )?;
                                    let (patterns, restores) = self.build_enum_patterns(
                                        args,
                                        variant_def,
                                        case_line,
                                        true,
                                    )?;
                                    let body = self.parse_statement()?;

                                    for (binding_name, previous) in restores {
                                        if let Some(prev_ty) = previous {
                                            self.pctx.var_types.insert(binding_name, prev_ty);
                                        } else {
                                            self.pctx.var_types.remove(&binding_name);
                                        }
                                    }

                                    arms.push(MatchArm::EnumDestructure {
                                        enum_name: enum_name.clone(),
                                        enum_type: matching_expr_type.clone(),
                                        variant: variant_name.clone(),
                                        patterns,
                                        body,
                                    });
                                    self.match_kind(TokenKind::Comma);
                                    handled_enum_pattern = true;
                                } else {
                                    return Err(format!(
                                        "Enum '{}' does not contain variant '{}'",
                                        enum_name, variant_name
                                    ));
                                }
                            }
                        }
                    }
                }

                if !handled_enum_pattern {
                    let is_option = matches!(matching_expr_type, Type::Option(_));
                    let is_result = matches!(matching_expr_type, Type::Result(_, _));
                    let variant_mismatch = match &matching {
                        Expr::OptionSome(_) | Expr::OptionNone => !is_option,
                        Expr::ResultOk(_) | Expr::ResultErr(_) => !is_result,
                        _ => false,
                    };

                    if variant_mismatch {
                        let variant = match &matching {
                            Expr::OptionSome(_) => "Some",
                            Expr::OptionNone => "None",
                            Expr::ResultOk(_) => "Ok",
                            Expr::ResultErr(_) => "Err",
                            _ => unreachable!(),
                        };
                        return Err(format!(
                            "Cannot match variant '{variant}' against value of type {matching_expr_type:?}."
                        ));
                    }

                    if let Expr::Get(enum_expr, variant_name) = &matching {
                        if let Expr::Variable(enum_name) = &**enum_expr {
                            if let Some(enum_variants) =
                                self.enum_variants_for_type(&matching_expr_type)
                            {
                                if let Some(variant_def) = enum_variants
                                    .iter()
                                    .find(|variant| variant.name == *variant_name)
                                {
                                    if !variant_def.payload.is_empty() {
                                        return Err(format!(
                                            "Variant '{}' expects {} argument(s), found 0",
                                            variant_name,
                                            variant_def.payload.len(),
                                        ));
                                    }
                                    self.consume(
                                        TokenKind::BigArrow,
                                        &format!(
                                            "Expected => in match statement, found {}",
                                            self.peek().kind
                                        ),
                                    )?;
                                    let body = self.parse_statement()?;
                                    arms.push(MatchArm::EnumDestructure {
                                        enum_name: enum_name.clone(),
                                        enum_type: matching_expr_type.clone(),
                                        variant: variant_name.clone(),
                                        patterns: Vec::new(),
                                        body,
                                    });
                                    self.match_kind(TokenKind::Comma);
                                    handled_enum_pattern = true;
                                } else {
                                    return Err(format!(
                                        "Enum '{}' does not contain variant '{}'",
                                        enum_name, variant_name
                                    ));
                                }
                            }
                        }
                    }
                }

                if handled_enum_pattern {
                    continue;
                }
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
                    eprintln!("Matching wrong type, expr is type {:?}", matching_expr_type);
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
            let (expr_line, var_name) = if let TokenKind::Identifier(n) = self.peek().kind.clone() {
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
                    self.pctx
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
            if expr_type == Type::Never {
                self.saw_never_return = true;
            }
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
                if value_type == Type::Never {
                    self.saw_never_return = true;
                }

                // Perform type enforcement based on left-hand side kind
                let types_compatible = |expected: &Type, value: &Type| -> bool {
                    if matches!(value, Type::Never) {
                        return true;
                    }
                    if expected == value {
                        true
                    } else if let Type::Option(expected_inner) = expected {
                        match value {
                            Type::Option(actual_inner) => {
                                if **actual_inner == Type::Never {
                                    true
                                } else {
                                    actual_inner == expected_inner
                                }
                            }
                            _ => false,
                        }
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
            if expr_type == Type::Never {
                self.saw_never_return = true;
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
                                    let val_ty = self.pctx.with_line(Some(lhs_line), || {
                                        args[1].get_type(&self.pctx)
                                    })?;
                                    self.pctx
                                        .var_types
                                        .insert(var_name.clone(), Type::Kv(Box::new(val_ty)));
                                }
                            }
                        }
                    }
                }
            }
            self.match_kind(TokenKind::Semicolon);
            Ok(Instruction::Expr(expr, expr_type))
        }
    }

    fn parse_type(&mut self) -> Result<Type, String> {
        match self.peek().kind {
            TokenKind::Bang => {
                self.advance();
                Ok(Type::Never)
            }
            LBrack => {
                self.advance();
                let inside = self.parse_type()?;

                self.consume(TokenKind::RBrack, "Expected ] after type for list type")?;
                Ok(Type::List(Box::new(inside)))
            }
            TokenKind::Identifier(ident) => {
                let name = ident.clone();
                if self.is_generic_param(&name) {
                    self.advance();
                    return Ok(Type::GenericParam(name));
                }

                let builtin = match name.as_str() {
                    "Str" => Some(Type::Str),
                    "Bool" => Some(Type::Bool),
                    "Num" => Some(Type::Num),
                    "JsonValue" => Some(Type::JsonValue),
                    "Obj" => None,
                    _ => None,
                };

                self.advance();

                let mut type_args = Vec::new();
                if self.match_kind(TokenKind::LParen) {
                    if self.match_kind(TokenKind::RParen) {
                        // allow empty list of args, treat as zero
                    } else {
                        loop {
                            let arg_ty = self.parse_type()?;
                            type_args.push(arg_ty);
                            if self.match_kind(TokenKind::RParen) {
                                break;
                            }
                            self.consume(
                                TokenKind::Comma,
                                "Expected ',' or ')' after type argument",
                            )?;
                        }
                    }
                }

                if let Some(resolved) = builtin {
                    if !type_args.is_empty() {
                        return Err(format!(
                            "Built-in type '{name}' does not accept type parameters"
                        ));
                    }
                    return Ok(resolved);
                }

                if name == "Option" {
                    if type_args.len() != 1 {
                        return Err(
                            "Option expects exactly one type parameter, e.g., Option(Str)"
                                .to_string(),
                        );
                    }
                    return Ok(Type::Option(Box::new(type_args[0].clone())));
                }

                if name == "Result" {
                    if type_args.len() != 2 {
                        return Err(
                            "Result expects exactly two type parameters, e.g., Result(Num, Str)"
                                .to_string(),
                        );
                    }
                    return Ok(Type::Result(
                        Box::new(type_args[0].clone()),
                        Box::new(type_args[1].clone()),
                    ));
                }

                if name == "Maybe" {
                    return Err(
                        "Maybe types have been removed. Use Option(...) instead.".to_string()
                    );
                }

                if name == "Obj" {
                    if type_args.len() != 1 {
                        return Err("Obj expects exactly one type parameter".to_string());
                    }
                    return Ok(Type::Kv(Box::new(type_args[0].clone())));
                }

                if let Some(concrete) = self.pctx.types.get(&name) {
                    if !type_args.is_empty() {
                        return Err(format!("Type '{name}' does not accept type parameters"));
                    }
                    return Ok(Type::Custom(concrete.clone()));
                }

                if self.pctx.generic_types.contains_key(&name) {
                    if type_args.is_empty() {
                        return Err(format!("Type '{name}' requires explicit type arguments"));
                    }
                    let instantiated = self.pctx.instantiate_generic_type(&name, &type_args)?;
                    return Ok(Type::Custom(instantiated));
                }

                Err(format!("Type {name} not found"))
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
            let param_type = self.parse_type()?;
            if self.match_kind(TokenKind::Comma) {
                // Continue parsing next parameter
            }
            params.push((param_name, param_type));
        }
        self.advance();

        // Insert parameter types into context for static type checking within function body
        let mut new_params = vec![];
        for (param_name, param_type) in &params {
            new_params.push((param_name.clone(), param_type.clone()));
            self.pctx
                .var_types
                .insert(param_name.clone(), param_type.clone());
        }

        // Reset return type inference and flags for this new function
        self.current_return_type = None;
        self.saw_non_nil_return = false;
        self.saw_nil_return = false;
        self.saw_never_return = false;

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
        } else if self.saw_nil_return {
            Type::Nil
        } else if self.saw_never_return {
            self.current_return_type.clone().unwrap_or(Type::Never)
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
                            let ty = self.pctx.with_line(None, || arg.get_type(&self.pctx))?;
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
        if self.match_kind(TokenKind::OptionNone) {
            return Ok(Expr::OptionNone);
        }
        if self.match_kind(TokenKind::OptionSome) {
            self.consume(TokenKind::LParen, "Some(...) requires parentheses")?;
            if self.check(&TokenKind::RParen) {
                return Err("Some expects exactly one value".to_string());
            }
            let value = self.expression()?;
            if self.match_kind(TokenKind::Comma) {
                return Err("Some expects exactly one value".to_string());
            }
            self.consume(
                TokenKind::RParen,
                "Expected ')' after value passed to Some(...)",
            )?;
            return Ok(Expr::OptionSome(Box::new(value)));
        }
        if self.match_kind(TokenKind::ResultOk) {
            self.consume(TokenKind::LParen, "Ok(...) requires parentheses")?;
            if self.check(&TokenKind::RParen) {
                return Err("Ok expects exactly one value".to_string());
            }
            let value = self.expression()?;
            if self.match_kind(TokenKind::Comma) {
                return Err("Ok expects exactly one value".to_string());
            }
            self.consume(
                TokenKind::RParen,
                "Expected ')' after value passed to Ok(...)",
            )?;
            return Ok(Expr::ResultOk(Box::new(value)));
        }
        if self.match_kind(TokenKind::ResultErr) {
            self.consume(TokenKind::LParen, "Err(...) requires parentheses")?;
            if self.check(&TokenKind::RParen) {
                return Err("Err expects exactly one value".to_string());
            }
            let value = self.expression()?;
            if self.match_kind(TokenKind::Comma) {
                return Err("Err expects exactly one value".to_string());
            }
            self.consume(
                TokenKind::RParen,
                "Expected ')' after value passed to Err(...)",
            )?;
            return Ok(Expr::ResultErr(Box::new(value)));
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
                        let real_type = self.pctx.with_line(None, || r_val.get_type(&self.pctx))?;

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
