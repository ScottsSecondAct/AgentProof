parser grammar AegisParser;
options { tokenVocab = AegisLexer; }

// ═══════════════════════════════════════════════════════════════════
//  Program structure
// ═══════════════════════════════════════════════════════════════════

program : declaration* EOF ;

declaration
  : importDeclaration
  | policyDeclaration
  | proofDeclaration
  | typeDeclaration
  | bindingDeclaration
  | functionDeclaration
  ;

// ═══════════════════════════════════════════════════════════════════
//  Imports
// ═══════════════════════════════════════════════════════════════════

importDeclaration
  : IMPORT importPath (AS ID)? SEMI
  | FROM importPath IMPORT importTargets SEMI
  ;
importPath    : ID (DOT ID)* ;
importTargets : importTarget (COMMA importTarget)* | MUL ;
importTarget  : ID (AS ID)? ;

// ═══════════════════════════════════════════════════════════════════
//  Policy — the primary top-level construct
//
//  policy DataExfiltrationGuard {
//      severity high
//      scope tool_call, data_access
//
//      on tool_call {
//          when event.tool contains "http" and event.destination != "internal"
//          deny with "External HTTP calls are not permitted"
//          log notify: "security-team"
//      }
//
//      proof NoExternalLeaks {
//          invariant NoHTTP {
//              always(context.tool_calls.all(t => !t.url.starts_with("http")))
//          }
//      }
//  }
// ═══════════════════════════════════════════════════════════════════

policyDeclaration
  : annotation*
    POLICY ID (EXTENDS qualifiedName)? LCURLY
      policyMember*
    RCURLY
  ;

policyMember
  : severityClause
  | scopeClause
  | ruleDeclaration
  | proofDeclaration
  | constraintDeclaration
  | bindingDeclaration
  | functionDeclaration
  ;

severityClause : SEVERITY severityLevel SEMI? ;
severityLevel  : SEV_CRITICAL | SEV_HIGH | SEV_MEDIUM | SEV_LOW | SEV_INFO ;

scopeClause    : SCOPE scopeTarget (COMMA scopeTarget)* SEMI? ;
scopeTarget    : qualifiedName | STRING ;

// ═══════════════════════════════════════════════════════════════════
//  Rules — event-triggered policy checks
//
//  on data_access {
//      when event.resource matches r"pii\..*"
//      redact fields: ["ssn", "email"]
//      audit with "PII access detected"
//      severity high
//  }
// ═══════════════════════════════════════════════════════════════════

ruleDeclaration
  : annotation*
    ON scopeTarget (COMMA scopeTarget)* LCURLY
      ruleBody
    RCURLY
  ;

ruleBody : ruleClause+ ;

ruleClause
  : whenClause
  | verdictClause
  | actionClause
  | severityClause
  | constraintDeclaration
  ;

whenClause    : WHEN expression SEMI? ;

verdictClause
  : verdict (WITH expression)? SEMI?
  ;
verdict : ALLOW | DENY | AUDIT | REDACT ;

actionClause
  : actionVerb actionArgs? SEMI?
  ;
actionVerb : LOG | NOTIFY | ESCALATE | BLOCK | TAG ;
actionArgs
  : expression
  | ID COLON expression (COMMA ID COLON expression)*
  ;

// ═══════════════════════════════════════════════════════════════════
//  Runtime constraints — rate limits and quotas
//
//  rate_limit tool_call: 100 per 1m
//  quota token_usage: 50000 per 1h
// ═══════════════════════════════════════════════════════════════════

constraintDeclaration
  : RATE_LIMIT qualifiedName COLON expression PER expression SEMI?
  | QUOTA qualifiedName COLON expression PER expression SEMI?
  ;

// ═══════════════════════════════════════════════════════════════════
//  Proofs and invariants (from olang — the moat)
//
//  proof BudgetSafety {
//      invariant SpendLimit {
//          always(context.total_spend <= policy.max_budget)
//      }
//      invariant EventualApproval {
//          eventually(context.approval_status == "approved") within 24h
//      }
//  }
// ═══════════════════════════════════════════════════════════════════

proofDeclaration
  : PROOF ID LCURLY
      invariantDeclaration*
    RCURLY
  ;

invariantDeclaration
  : INVARIANT ID LCURLY
      expression (SEMI expression)* SEMI?
    RCURLY
  ;

// ═══════════════════════════════════════════════════════════════════
//  Types — lean subset, no Future/Pipeline/Provenance/Stream
// ═══════════════════════════════════════════════════════════════════

typeDeclaration : TYPE ID genericParams? LCURLY typedFieldList RCURLY ;

type : baseType (UNION_PIPE baseType)* ;
baseType
  : primitiveType
  | listType
  | mapType
  | setType
  | userDefinedType
  | LPAREN type RPAREN
  ;
primitiveType   : INT_TYPE | FLOAT_TYPE | BOOL_TYPE | STRING_TYPE | DURATION_TYPE ;
listType        : LIST_TYPE LT type GT ;
mapType         : MAP_TYPE LT type COMMA type GT ;
setType         : SET_TYPE LT type GT ;
userDefinedType : qualifiedName genericArgs? ;

genericParams   : LT genericParam (COMMA genericParam)* GT ;
genericParam    : ID (EXTENDS type)? ;
genericArgs     : LT type (COMMA type)* GT ;

typedField      : ID COLON type ;
typedFieldList  : typedField (COMMA typedField)* COMMA? ;
typedParam      : ID COLON type ;
typedParamList  : typedParam (COMMA typedParam)* ;

// ═══════════════════════════════════════════════════════════════════
//  Bindings and functions
// ═══════════════════════════════════════════════════════════════════

bindingDeclaration  : LET ID (COLON type)? EQUALS expression SEMI? ;
functionDeclaration : DEF ID LPAREN typedParamList? RPAREN ARROW type EQUALS expression SEMI? ;

// ═══════════════════════════════════════════════════════════════════
//  Expressions — verification-focused precedence hierarchy
//
//  Precedence (low → high):
//    implies → or → and → equality → relational →
//    temporal → additive → multiplicative → unary →
//    postfix → primary
// ═══════════════════════════════════════════════════════════════════

expression : impliesExpression ;

impliesExpression
  : logicalOrExpression (IMPLIES logicalOrExpression)?
  ;

logicalOrExpression
  : logicalAndExpression ((OR_OP | OR) logicalAndExpression)*
  ;

logicalAndExpression
  : equalityExpression ((AND_OP | AND) equalityExpression)*
  ;

equalityExpression
  : relationalExpression ((EQ | NEQ) relationalExpression)*
  ;

relationalExpression
  : temporalExpression ((LE | LT | GE | GT | IN) temporalExpression)*
  ;

// Temporal operators sit above arithmetic — they bind tighter than
// comparison but looser than the math layer. This lets you write:
//   always(x > 5)           — temporal wrapping comparison
//   eventually(a + b < 10)  — temporal wrapping arithmetic comparison
temporalExpression
  : additiveExpression
  | ALWAYS  LPAREN expression RPAREN (WITHIN expression)?
  | EVENTUALLY LPAREN expression RPAREN (WITHIN expression)?
  | NEVER   LPAREN expression RPAREN
  | expression UNTIL expression
  | NEXT    LPAREN expression RPAREN
  | BEFORE  LPAREN expression COMMA expression RPAREN
  | AFTER   LPAREN expression COMMA expression RPAREN
  ;

additiveExpression
  : multiplicativeExpression ((ADD | SUB) multiplicativeExpression)*
  ;

multiplicativeExpression
  : unaryExpression ((MUL | DIV | MOD) unaryExpression)*
  ;

unaryExpression
  : (NOT | SUB) unaryExpression
  | postfixExpression
  ;

postfixExpression
  : primaryExpression postfixOp*
  ;

postfixOp
  : DOT ID callArgs?                   // field access or method call
  | LBRACK expression RBRACK           // index access
  | callArgs                            // direct call
  | CONTAINS expression                 // x contains y
  | MATCHES expression                  // x matches /regex/
  | STARTS_WITH expression              // x starts_with "prefix"
  | ENDS_WITH expression                // x ends_with "suffix"
  ;

callArgs : LPAREN argumentList? RPAREN ;

// ═══════════════════════════════════════════════════════════════════
//  Primary expressions
// ═══════════════════════════════════════════════════════════════════

primaryExpression
  : literalValue
  | qualifiedName
  | contextExpression
  | matchExpression
  | quantifierExpression
  | countExpression
  | listExpression
  | objectExpression
  | lambdaExpression
  | LPAREN expression RPAREN
  ;

// context.tool_calls, context.user, context.session
contextExpression : CONTEXT DOT qualifiedName ;

// Quantifiers over collections
//   all(context.tools, t => t.approved)
//   any(event.tags, tag => tag == "sensitive")
//   none(context.urls, u => u.starts_with("http://"))
//   exists(context.approvals, a => a.role == "admin")
quantifierExpression
  : (ALL | ANY | NONE | EXISTS) LPAREN expression COMMA lambdaExpression RPAREN
  ;

// count(context.api_calls, c => c.method == "POST")
countExpression
  : COUNT LPAREN expression (COMMA lambdaExpression)? RPAREN
  ;

// ═══════════════════════════════════════════════════════════════════
//  Pattern matching (from olang — essential for event routing)
//
//  match event.type {
//      "tool_call"   -> deny with "Tools disabled"
//      "data_read"   -> audit
//      _             -> allow
//  }
// ═══════════════════════════════════════════════════════════════════

matchExpression : MATCH expression LCURLY matchArm (COMMA matchArm)* COMMA? RCURLY ;
matchArm        : pattern ARROW matchResult ;
matchResult     : expression | verdictClause | blockExpression ;

pattern         : orPattern ;
orPattern       : primaryPattern (UNION_PIPE primaryPattern)* ;
primaryPattern
  : WILDCARD                                            // _
  | literalValue                                        // "tool_call", 42, true
  | ID                                                  // binding
  | qualifiedName LCURLY patternFieldList? RCURLY       // ToolCall { name: "http" }
  | LBRACK patternList? RBRACK                          // [first, second, _]
  | primaryPattern WHEN expression                      // x when x > 10
  | LPAREN pattern RPAREN                               // (grouped)
  ;

patternFieldList : patternField (COMMA patternField)* COMMA? ;
patternField     : ID COLON pattern | ID | WILDCARD ;
patternList      : pattern (COMMA pattern)* COMMA? ;

// ═══════════════════════════════════════════════════════════════════
//  Lambda expressions (simplified from olang — no destructuring)
// ═══════════════════════════════════════════════════════════════════

lambdaExpression
  : ID IMPLIES_OP expression                             // x => x > 5
  | LPAREN lambdaParamList RPAREN IMPLIES_OP expression  // (x, y) => x + y
  ;

lambdaParamList : lambdaParam (COMMA lambdaParam)* ;
lambdaParam     : ID (COLON type)? ;

// ═══════════════════════════════════════════════════════════════════
//  Block expressions and annotations
// ═══════════════════════════════════════════════════════════════════

blockExpression : LCURLY blockStatement* RCURLY ;
blockStatement
  : bindingDeclaration
  | expression SEMI?
  | verdictClause
  | actionClause
  ;

annotation     : AT ID (LPAREN annotationArgs RPAREN)? ;
annotationArgs : annotationArg (COMMA annotationArg)* ;
annotationArg  : ID COLON annotationValue | annotationValue ;
annotationValue: literalValue | listLiteral ;
listLiteral    : LBRACK (annotationValue (COMMA annotationValue)*)? RBRACK ;

// ═══════════════════════════════════════════════════════════════════
//  Collection literals, arguments, names, literals
// ═══════════════════════════════════════════════════════════════════

listExpression   : LBRACK (expression (COMMA expression)*)? RBRACK ;
objectExpression : LCURLY (objectField (COMMA objectField)* COMMA?)? RCURLY ;
objectField      : (ID | STRING) COLON expression ;

argumentList : argument (COMMA argument)* ;
argument     : ID EQUALS expression | expression ;

qualifiedName : ID (DOT ID)* ;

literalValue
  : BOOLEAN
  | INT_LITERAL
  | FLOAT_LITERAL
  | DURATION_LITERAL
  | STRING
  | RAW_STRING
  | REGEX_LITERAL
  ;
