use std::collections::HashMap;
use std::fmt;

use smol_str::SmolStr;

use crate::ast::{PrimitiveType, Span, Spanned};

/// A unique identifier for a type in the type environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeId(pub u32);

/// Semantic types — the resolved representation used during checking.
///
/// Distinct from `ast::Type` which represents surface syntax. The checker
/// resolves `ast::Type` into `Ty` after name resolution and generic
/// instantiation.
#[derive(Debug, Clone, PartialEq)]
pub enum Ty {
    /// Primitive: `int`, `float`, `bool`, `string`, `duration`
    Primitive(PrimitiveType),

    /// `List<T>`
    List(Box<Ty>),

    /// `Map<K, V>`
    Map(Box<Ty>, Box<Ty>),

    /// `Set<T>`
    Set(Box<Ty>),

    /// A user-defined struct type
    Struct(StructType),

    /// `A | B` — union type
    Union(Vec<Ty>),

    /// A function type: `(params) -> return`
    Function { params: Vec<Ty>, ret: Box<Ty> },

    /// Verdict type — the result of a rule evaluation
    Verdict,

    /// The type of temporal expressions (used in proof checking)
    Temporal,

    /// A type variable (for generic type checking)
    Var(TypeId),

    /// The bottom type — used for `never` / unreachable
    Never,

    /// A type that failed to resolve (prevents cascading errors)
    Error,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StructType {
    pub name: SmolStr,
    pub fields: Vec<(SmolStr, Ty)>,
    pub type_params: Vec<Ty>,
}

impl Ty {
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Ty::Primitive(PrimitiveType::Int) | Ty::Primitive(PrimitiveType::Float)
        )
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, Ty::Primitive(PrimitiveType::Bool))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Ty::Primitive(PrimitiveType::String))
    }

    pub fn is_duration(&self) -> bool {
        matches!(self, Ty::Primitive(PrimitiveType::Duration))
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Ty::Error)
    }

    pub fn is_collection(&self) -> bool {
        matches!(self, Ty::List(_) | Ty::Set(_))
    }

    /// The element type if this is a collection, None otherwise.
    pub fn element_type(&self) -> Option<&Ty> {
        match self {
            Ty::List(inner) | Ty::Set(inner) => Some(inner),
            _ => None,
        }
    }

    /// Check if `self` is a subtype of `other`.
    ///
    /// Subtyping rules for Aegis:
    /// - `never` is a subtype of everything
    /// - `Error` is compatible with everything (suppresses cascading errors)
    /// - `int` is a subtype of `float` (numeric widening)
    /// - `A` is a subtype of `A | B`
    /// - Structural subtyping for structs (every field in `other` exists in `self`)
    pub fn is_subtype_of(&self, other: &Ty) -> bool {
        if self == other {
            return true;
        }
        match (self, other) {
            // Error suppresses cascading
            (Ty::Error, _) | (_, Ty::Error) => true,
            // Never is bottom
            (Ty::Never, _) => true,
            // Numeric widening
            (Ty::Primitive(PrimitiveType::Int), Ty::Primitive(PrimitiveType::Float)) => true,
            // Union subtyping: T <: T | U
            (_, Ty::Union(members)) => members.iter().any(|m| self.is_subtype_of(m)),
            // Collection covariance
            (Ty::List(a), Ty::List(b)) => a.is_subtype_of(b),
            (Ty::Set(a), Ty::Set(b)) => a.is_subtype_of(b),
            (Ty::Map(ak, av), Ty::Map(bk, bv)) => ak.is_subtype_of(bk) && av.is_subtype_of(bv),
            _ => false,
        }
    }
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ty::Primitive(p) => match p {
                PrimitiveType::Int => write!(f, "int"),
                PrimitiveType::Float => write!(f, "float"),
                PrimitiveType::Bool => write!(f, "bool"),
                PrimitiveType::String => write!(f, "string"),
                PrimitiveType::Duration => write!(f, "duration"),
            },
            Ty::List(inner) => write!(f, "List<{inner}>"),
            Ty::Map(k, v) => write!(f, "Map<{k}, {v}>"),
            Ty::Set(inner) => write!(f, "Set<{inner}>"),
            Ty::Struct(s) => write!(f, "{}", s.name),
            Ty::Union(members) => {
                let parts: Vec<_> = members.iter().map(|m| m.to_string()).collect();
                write!(f, "{}", parts.join(" | "))
            }
            Ty::Function { params, ret } => {
                let ps: Vec<_> = params.iter().map(|p| p.to_string()).collect();
                write!(f, "({}) -> {ret}", ps.join(", "))
            }
            Ty::Verdict => write!(f, "verdict"),
            Ty::Temporal => write!(f, "temporal"),
            Ty::Var(id) => write!(f, "?T{}", id.0),
            Ty::Never => write!(f, "never"),
            Ty::Error => write!(f, "<error>"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Type environment — tracks type definitions and bindings in scope
// ═══════════════════════════════════════════════════════════════════════

/// A scope in the type environment. Scopes are nested (function body
/// inside policy body inside module scope).
#[derive(Debug, Clone)]
pub struct Scope {
    /// Name → type bindings (variables, parameters, let bindings)
    pub bindings: HashMap<SmolStr, Ty>,
    /// Named type definitions
    pub types: HashMap<SmolStr, Ty>,
    /// Function signatures
    pub functions: HashMap<SmolStr, FunctionSig>,
}

#[derive(Debug, Clone)]
pub struct FunctionSig {
    pub params: Vec<(SmolStr, Ty)>,
    pub ret: Ty,
}

impl Scope {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            types: HashMap::new(),
            functions: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct TypeEnv {
    scopes: Vec<Scope>,
    next_type_id: u32,
}

impl TypeEnv {
    pub fn new() -> Self {
        let mut env = Self {
            scopes: vec![Scope::new()],
            next_type_id: 0,
        };
        env.register_builtins();
        env
    }

    /// Register built-in types and functions available in every Aegis policy.
    fn register_builtins(&mut self) {
        let scope = self.scopes.last_mut().unwrap();

        // The `event` binding is always available inside rule bodies.
        // Its actual type is refined per-scope based on the `on` clause.
        scope.bindings.insert(
            SmolStr::new("event"),
            Ty::Struct(StructType {
                name: SmolStr::new("Event"),
                fields: vec![
                    (SmolStr::new("type"), Ty::Primitive(PrimitiveType::String)),
                    (
                        SmolStr::new("timestamp"),
                        Ty::Primitive(PrimitiveType::Duration),
                    ),
                ],
                type_params: vec![],
            }),
        );

        // The `policy` binding refers to the enclosing policy's config.
        scope.bindings.insert(
            SmolStr::new("policy"),
            Ty::Struct(StructType {
                name: SmolStr::new("PolicyConfig"),
                fields: vec![],
                type_params: vec![],
            }),
        );
    }

    pub fn push_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    pub fn pop_scope(&mut self) {
        assert!(self.scopes.len() > 1, "Cannot pop the global scope");
        self.scopes.pop();
    }

    pub fn current_scope_mut(&mut self) -> &mut Scope {
        self.scopes.last_mut().unwrap()
    }

    /// Look up a binding by name, searching from innermost to outermost scope.
    pub fn lookup_binding(&self, name: &str) -> Option<&Ty> {
        for scope in self.scopes.iter().rev() {
            if let Some(ty) = scope.bindings.get(name) {
                return Some(ty);
            }
        }
        None
    }

    /// Look up a named type definition.
    pub fn lookup_type(&self, name: &str) -> Option<&Ty> {
        for scope in self.scopes.iter().rev() {
            if let Some(ty) = scope.types.get(name) {
                return Some(ty);
            }
        }
        None
    }

    /// Look up a function signature.
    pub fn lookup_function(&self, name: &str) -> Option<&FunctionSig> {
        for scope in self.scopes.iter().rev() {
            if let Some(sig) = scope.functions.get(name) {
                return Some(sig);
            }
        }
        None
    }

    pub fn bind(&mut self, name: SmolStr, ty: Ty) {
        self.current_scope_mut().bindings.insert(name, ty);
    }

    pub fn define_type(&mut self, name: SmolStr, ty: Ty) {
        self.current_scope_mut().types.insert(name, ty);
    }

    pub fn define_function(&mut self, name: SmolStr, sig: FunctionSig) {
        self.current_scope_mut().functions.insert(name, sig);
    }

    pub fn fresh_type_var(&mut self) -> Ty {
        let id = TypeId(self.next_type_id);
        self.next_type_id += 1;
        Ty::Var(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::PrimitiveType;

    fn int() -> Ty {
        Ty::Primitive(PrimitiveType::Int)
    }
    fn float() -> Ty {
        Ty::Primitive(PrimitiveType::Float)
    }
    fn bool_ty() -> Ty {
        Ty::Primitive(PrimitiveType::Bool)
    }
    fn string_ty() -> Ty {
        Ty::Primitive(PrimitiveType::String)
    }
    fn duration_ty() -> Ty {
        Ty::Primitive(PrimitiveType::Duration)
    }

    // ── Ty property checks ───────────────────────────────────────────────

    #[test]
    fn is_numeric_for_int_and_float_only() {
        assert!(int().is_numeric());
        assert!(float().is_numeric());
        assert!(!bool_ty().is_numeric());
        assert!(!string_ty().is_numeric());
        assert!(!duration_ty().is_numeric());
    }

    #[test]
    fn is_bool_for_bool_only() {
        assert!(bool_ty().is_bool());
        assert!(!int().is_bool());
        assert!(!string_ty().is_bool());
    }

    #[test]
    fn is_string_for_string_only() {
        assert!(string_ty().is_string());
        assert!(!int().is_string());
        assert!(!bool_ty().is_string());
    }

    #[test]
    fn is_duration_for_duration_only() {
        assert!(duration_ty().is_duration());
        assert!(!int().is_duration());
        assert!(!string_ty().is_duration());
    }

    #[test]
    fn is_collection_for_list_and_set_not_map() {
        assert!(Ty::List(Box::new(int())).is_collection());
        assert!(Ty::Set(Box::new(int())).is_collection());
        assert!(!int().is_collection());
        assert!(!Ty::Map(Box::new(string_ty()), Box::new(int())).is_collection());
    }

    #[test]
    fn element_type_for_list_and_set() {
        assert_eq!(Ty::List(Box::new(int())).element_type(), Some(&int()));
        assert_eq!(
            Ty::Set(Box::new(string_ty())).element_type(),
            Some(&string_ty())
        );
        assert_eq!(int().element_type(), None);
        assert_eq!(
            Ty::Map(Box::new(int()), Box::new(string_ty())).element_type(),
            None
        );
    }

    #[test]
    fn is_error_only_for_error_variant() {
        assert!(Ty::Error.is_error());
        assert!(!int().is_error());
        assert!(!Ty::Never.is_error());
    }

    // ── Subtyping ────────────────────────────────────────────────────────

    #[test]
    fn subtype_reflexive_for_primitives() {
        assert!(int().is_subtype_of(&int()));
        assert!(float().is_subtype_of(&float()));
        assert!(bool_ty().is_subtype_of(&bool_ty()));
        assert!(string_ty().is_subtype_of(&string_ty()));
    }

    #[test]
    fn subtype_error_suppresses_cascading_both_directions() {
        assert!(Ty::Error.is_subtype_of(&int()));
        assert!(Ty::Error.is_subtype_of(&string_ty()));
        assert!(int().is_subtype_of(&Ty::Error));
        assert!(string_ty().is_subtype_of(&Ty::Error));
    }

    #[test]
    fn subtype_never_is_bottom_type() {
        assert!(Ty::Never.is_subtype_of(&int()));
        assert!(Ty::Never.is_subtype_of(&string_ty()));
        assert!(Ty::Never.is_subtype_of(&bool_ty()));
        assert!(Ty::Never.is_subtype_of(&Ty::Never));
        assert!(Ty::Never.is_subtype_of(&Ty::Error));
    }

    #[test]
    fn subtype_int_widens_to_float_not_reverse() {
        assert!(int().is_subtype_of(&float()));
        assert!(!float().is_subtype_of(&int()));
    }

    #[test]
    fn subtype_unrelated_primitives_incompatible() {
        assert!(!int().is_subtype_of(&bool_ty()));
        assert!(!string_ty().is_subtype_of(&int()));
        assert!(!bool_ty().is_subtype_of(&string_ty()));
        assert!(!float().is_subtype_of(&string_ty()));
    }

    #[test]
    fn subtype_member_of_union() {
        let union = Ty::Union(vec![int(), string_ty()]);
        assert!(int().is_subtype_of(&union));
        assert!(string_ty().is_subtype_of(&union));
        assert!(!bool_ty().is_subtype_of(&union));
    }

    #[test]
    fn subtype_int_in_union_containing_float_via_widening() {
        // int <: float, and float ∈ union, so int <: union
        let union = Ty::Union(vec![float(), string_ty()]);
        assert!(int().is_subtype_of(&union));
    }

    #[test]
    fn subtype_list_covariant() {
        // int <: float ⟹ List<int> <: List<float>
        assert!(Ty::List(Box::new(int())).is_subtype_of(&Ty::List(Box::new(float()))));
        assert!(!Ty::List(Box::new(float())).is_subtype_of(&Ty::List(Box::new(int()))));
    }

    #[test]
    fn subtype_set_covariant() {
        assert!(Ty::Set(Box::new(int())).is_subtype_of(&Ty::Set(Box::new(float()))));
        assert!(!Ty::Set(Box::new(float())).is_subtype_of(&Ty::Set(Box::new(int()))));
    }

    #[test]
    fn subtype_map_covariant_in_both_params() {
        let m_int_str = Ty::Map(Box::new(int()), Box::new(string_ty()));
        let m_float_str = Ty::Map(Box::new(float()), Box::new(string_ty()));
        assert!(m_int_str.is_subtype_of(&m_float_str));
        assert!(!m_float_str.is_subtype_of(&m_int_str));
    }

    #[test]
    fn subtype_list_not_subtype_of_set() {
        assert!(!Ty::List(Box::new(int())).is_subtype_of(&Ty::Set(Box::new(int()))));
    }

    // ── TypeEnv ──────────────────────────────────────────────────────────

    #[test]
    fn new_env_contains_builtin_event_binding() {
        let env = TypeEnv::new();
        assert!(env.lookup_binding("event").is_some());
    }

    #[test]
    fn new_env_contains_builtin_policy_binding() {
        let env = TypeEnv::new();
        assert!(env.lookup_binding("policy").is_some());
    }

    #[test]
    fn lookup_missing_binding_returns_none() {
        let env = TypeEnv::new();
        assert!(env.lookup_binding("undefined_var").is_none());
    }

    #[test]
    fn lookup_missing_type_returns_none() {
        let env = TypeEnv::new();
        assert!(env.lookup_type("UnknownType").is_none());
    }

    #[test]
    fn lookup_missing_function_returns_none() {
        let env = TypeEnv::new();
        assert!(env.lookup_function("unknown_fn").is_none());
    }

    #[test]
    fn bind_and_lookup_in_same_scope() {
        let mut env = TypeEnv::new();
        env.bind(SmolStr::new("x"), int());
        assert_eq!(env.lookup_binding("x"), Some(&int()));
    }

    #[test]
    fn inner_scope_shadows_outer_binding() {
        let mut env = TypeEnv::new();
        env.bind(SmolStr::new("x"), int());
        env.push_scope();
        env.bind(SmolStr::new("x"), string_ty());
        assert_eq!(env.lookup_binding("x"), Some(&string_ty()));
    }

    #[test]
    fn pop_scope_restores_outer_binding() {
        let mut env = TypeEnv::new();
        env.bind(SmolStr::new("x"), int());
        env.push_scope();
        env.bind(SmolStr::new("x"), string_ty());
        env.pop_scope();
        assert_eq!(env.lookup_binding("x"), Some(&int()));
    }

    #[test]
    fn inner_scope_can_see_outer_bindings() {
        let mut env = TypeEnv::new();
        env.bind(SmolStr::new("outer"), int());
        env.push_scope();
        assert_eq!(env.lookup_binding("outer"), Some(&int()));
        env.pop_scope();
    }

    #[test]
    fn popped_scope_binding_no_longer_visible() {
        let mut env = TypeEnv::new();
        env.push_scope();
        env.bind(SmolStr::new("local"), bool_ty());
        env.pop_scope();
        assert!(env.lookup_binding("local").is_none());
    }

    #[test]
    fn define_and_lookup_type() {
        let mut env = TypeEnv::new();
        env.define_type(SmolStr::new("MyStruct"), string_ty());
        assert_eq!(env.lookup_type("MyStruct"), Some(&string_ty()));
    }

    #[test]
    fn define_and_lookup_function() {
        let mut env = TypeEnv::new();
        let sig = FunctionSig {
            params: vec![(SmolStr::new("n"), int())],
            ret: bool_ty(),
        };
        env.define_function(SmolStr::new("is_even"), sig);
        let found = env.lookup_function("is_even").expect("should find fn");
        assert_eq!(found.ret, bool_ty());
        assert_eq!(found.params[0].1, int());
    }

    #[test]
    fn fresh_type_vars_are_distinct() {
        let mut env = TypeEnv::new();
        let v1 = env.fresh_type_var();
        let v2 = env.fresh_type_var();
        let v3 = env.fresh_type_var();
        assert_ne!(v1, v2);
        assert_ne!(v2, v3);
        assert_ne!(v1, v3);
    }

    #[test]
    fn fresh_type_vars_are_var_variants() {
        let mut env = TypeEnv::new();
        assert!(matches!(env.fresh_type_var(), Ty::Var(_)));
    }

    #[test]
    fn type_ids_increment_sequentially() {
        let mut env = TypeEnv::new();
        let Ty::Var(TypeId(id1)) = env.fresh_type_var() else {
            panic!()
        };
        let Ty::Var(TypeId(id2)) = env.fresh_type_var() else {
            panic!()
        };
        assert_eq!(id2, id1 + 1);
    }
}
