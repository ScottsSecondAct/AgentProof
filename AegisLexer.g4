lexer grammar AegisLexer;

// ─── Policy structure ───────────────────────────────────────────────
POLICY:     'policy';
SCOPE:      'scope';
ON:         'on';
RULE:       'rule';
WHEN:       'when';
WHERE:      'where';
IN:         'in';

// ─── Verdicts ───────────────────────────────────────────────────────
ALLOW:      'allow';
DENY:       'deny';
AUDIT:      'audit';
REDACT:     'redact';

// ─── Verification / temporal logic (from olang) ─────────────────────
PROOF:      'proof';
INVARIANT:  'invariant';
ASSERT:     'assert';
ALWAYS:     'always';
EVENTUALLY: 'eventually';
NEVER:      'never';
UNTIL:      'until';
BEFORE:     'before';
AFTER:      'after';
NEXT:       'next';
WITHIN:     'within';
DURING:     'during';

// ─── Quantifiers ────────────────────────────────────────────────────
ANY:        'any';
ALL:        'all';
NONE:       'none';
EXISTS:     'exists';

// ─── Declarations ───────────────────────────────────────────────────
IMPORT:     'import';
FROM:       'from';
AS:         'as';
LET:        'let';
DEF:        'def';
TYPE:       'type';
EXTENDS:    'extends';
WITH:       'with';
MATCH:      'match';

// ─── Runtime constraints ────────────────────────────────────────────
RATE_LIMIT: 'rate_limit';
QUOTA:      'quota';
SEVERITY:   'severity';
CONTEXT:    'context';
COUNT:      'count';
PER:        'per';

// ─── Actions ────────────────────────────────────────────────────────
LOG:        'log';
NOTIFY:     'notify';
ESCALATE:   'escalate';
BLOCK:      'block';
TAG:        'tag';

// ─── Built-in predicates ────────────────────────────────────────────
CONTAINS:    'contains';
MATCHES:     'matches';
STARTS_WITH: 'starts_with';
ENDS_WITH:   'ends_with';
IMPLIES:     'implies';

// ─── Primitive types ────────────────────────────────────────────────
INT_TYPE:    'int';
FLOAT_TYPE:  'float';
BOOL_TYPE:   'bool';
STRING_TYPE: 'string';
DURATION_TYPE: 'duration';
LIST_TYPE:   'List';
MAP_TYPE:    'Map';
SET_TYPE:    'Set';

// ─── Severity levels (enum-like) ────────────────────────────────────
SEV_CRITICAL: 'critical';
SEV_HIGH:     'high';
SEV_MEDIUM:   'medium';
SEV_LOW:      'low';
SEV_INFO:     'info';

// ─── Operators ──────────────────────────────────────────────────────
ADD:        '+';
SUB:        '-';
MUL:        '*';
DIV:        '/';
MOD:        '%';
EQ:         '==';
NEQ:        '!=';
LE:         '<=';
LT:         '<';
GE:         '>=';
GT:         '>';
AND_OP:     '&&';
OR_OP:      '||';
NOT:        '!';
AND:        'and';
OR:         'or';
IMPLIES_OP: '=>';
ARROW:      '->';
UNION_PIPE: '|';
RANGE_OP:   '..';
WILDCARD:   '_';

// ─── Literals ───────────────────────────────────────────────────────
BOOLEAN:          'true' | 'false';
INT_LITERAL:      DIGIT+;
FLOAT_LITERAL:    DIGIT+ '.' DIGIT+ ([eE][+-]? DIGIT+)?;
DURATION_LITERAL: DIGIT+ ('ms' | 's' | 'm' | 'h' | 'd');
STRING:           '"' STR_CONTENT* '"';
RAW_STRING:       'r"' (~["])* '"';
REGEX_LITERAL:    '/' REGEX_CONTENT+ '/' REGEX_FLAGS?;

// ─── Delimiters ─────────────────────────────────────────────────────
LPAREN:     '(';
RPAREN:     ')';
LBRACK:     '[';
RBRACK:     ']';
LCURLY:     '{';
RCURLY:     '}';
DOT:        '.';
COMMA:      ',';
COLON:      ':';
SEMI:       ';';
EQUALS:     '=';
AT:         '@';
HASH:       '#';

// ─── Identifiers & whitespace ───────────────────────────────────────
ID:            ID_START ID_CONTINUE*;
COMMENT:       '//' ~[\r\n]* -> skip;
BLOCK_COMMENT: '/*' .*? '*/' -> skip;
WS:            [ \t\r\n]+ -> skip;

// ─── Fragments ──────────────────────────────────────────────────────
fragment DIGIT:         [0-9];
fragment ID_START:      [\p{L}_];
fragment ID_CONTINUE:   [\p{L}\p{N}_];
fragment STR_CONTENT:   EscapeSequence | ~["\\\r\n];
fragment EscapeSequence: '\\' ([btnfr"'\\] | UnicodeEscape);
fragment UnicodeEscape:
    'u' HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT
  | 'U' HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT
        HEX_DIGIT HEX_DIGIT HEX_DIGIT HEX_DIGIT;
fragment HEX_DIGIT:     [0-9a-fA-F];
fragment REGEX_CONTENT: ~[/\r\n\\] | '\\' .;
fragment REGEX_FLAGS:   [gimsx]+;
