//! Lexer and recursive-descent parser.

use crate::error::{QueryError, Span};
use crate::limits::Limits;
use crate::syntax::{BinaryOp, Expr, Field, Literal};

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    String(String),
    Eq,
    Ne,
    And,
    Or,
    LParen,
    RParen,
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    span: Span,
}

/// Parse a query string into an [`Expr`] under [`Limits`].
///
/// # Errors
///
/// Lex, parse, or limit failures with spans where applicable.
pub fn parse(input: &str, limits: &Limits) -> Result<Expr, QueryError> {
    if input.len() > limits.max_input_bytes {
        return Err(QueryError::Limit {
            reason: format!(
                "input is {} bytes; max is {}",
                input.len(),
                limits.max_input_bytes
            ),
        });
    }
    let tokens = lex(input, limits)?;
    let mut parser = Parser {
        tokens: &tokens,
        index: 0,
    };
    let expr = parser.parse_or()?;
    parser.expect_eof()?;
    if expr.depth() > limits.max_depth {
        return Err(QueryError::Limit {
            reason: format!(
                "expression depth {} exceeds max {}",
                expr.depth(),
                limits.max_depth
            ),
        });
    }
    Ok(expr)
}

fn lex(input: &str, limits: &Limits) -> Result<Vec<Token>, QueryError> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        if tokens.len() >= limits.max_tokens {
            return Err(QueryError::Limit {
                reason: format!("more than {} tokens", limits.max_tokens),
            });
        }
        let start = i;
        let Some(&b) = bytes.get(i) else {
            break;
        };
        // whitespace
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // punctuation / operators
        if b == b'(' {
            tokens.push(Token {
                kind: TokenKind::LParen,
                span: Span::new(start, start + 1),
            });
            i += 1;
            continue;
        }
        if b == b')' {
            tokens.push(Token {
                kind: TokenKind::RParen,
                span: Span::new(start, start + 1),
            });
            i += 1;
            continue;
        }
        if b == b'=' {
            tokens.push(Token {
                kind: TokenKind::Eq,
                span: Span::new(start, start + 1),
            });
            i += 1;
            continue;
        }
        if b == b'!' && bytes.get(i + 1) == Some(&b'=') {
            tokens.push(Token {
                kind: TokenKind::Ne,
                span: Span::new(start, start + 2),
            });
            i += 2;
            continue;
        }
        // double-quoted string
        if b == b'"' {
            i += 1;
            let mut out = String::new();
            let mut closed = false;
            while i < bytes.len() {
                let Some(&c) = bytes.get(i) else {
                    break;
                };
                if c == b'"' {
                    i += 1;
                    tokens.push(Token {
                        kind: TokenKind::String(out),
                        span: Span::new(start, i),
                    });
                    closed = true;
                    break;
                }
                if c == b'\\' {
                    i += 1;
                    let Some(&escaped) = bytes.get(i) else {
                        return Err(QueryError::Lex {
                            reason: "unterminated escape in string".to_owned(),
                            start,
                            end: i,
                        });
                    };
                    out.push(char::from(escaped));
                    i += 1;
                    continue;
                }
                out.push(char::from(c));
                i += 1;
            }
            if closed {
                continue;
            }
            return Err(QueryError::Lex {
                reason: "unterminated string".to_owned(),
                start,
                end: i,
            });
        }
        // identifier / keyword
        if b.is_ascii_alphabetic() || b == b'_' {
            i += 1;
            while i < bytes.len() {
                let Some(&c) = bytes.get(i) else {
                    break;
                };
                if c.is_ascii_alphanumeric() || c == b'_' || c == b'-' {
                    i += 1;
                } else {
                    break;
                }
            }
            let text = input
                .get(start..i)
                .ok_or_else(|| QueryError::Lex {
                    reason: "invalid identifier span".to_owned(),
                    start,
                    end: i,
                })?
                .to_owned();
            let kind = match text.as_str() {
                "and" | "AND" => TokenKind::And,
                "or" | "OR" => TokenKind::Or,
                _ => TokenKind::Ident(text),
            };
            tokens.push(Token {
                kind,
                span: Span::new(start, i),
            });
            continue;
        }

        // Reject SQL-looking noise explicitly.
        if matches!(b, b';' | b'-' | b'/' | b'*' | b'`') {
            return Err(QueryError::Lex {
                reason: format!(
                    "character {:?} is not allowed (no SQL, comments, or wildcards)",
                    char::from(b)
                ),
                start,
                end: start + 1,
            });
        }

        return Err(QueryError::Lex {
            reason: format!("unexpected character {:?}", char::from(b)),
            start,
            end: start + 1,
        });
    }

    tokens.push(Token {
        kind: TokenKind::Eof,
        span: Span::new(input.len(), input.len()),
    });
    if tokens.len() > limits.max_tokens {
        return Err(QueryError::Limit {
            reason: format!("more than {} tokens", limits.max_tokens),
        });
    }
    Ok(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    index: usize,
}

impl Parser<'_> {
    fn current(&self) -> &Token {
        // Lexer always appends Eof.
        if let Some(token) = self.tokens.get(self.index) {
            token
        } else if let Some(token) = self.tokens.last() {
            token
        } else {
            // Unreachable after a successful lex; keep the type happy without panic.
            static EOF: Token = Token {
                kind: TokenKind::Eof,
                span: Span::new(0, 0),
            };
            &EOF
        }
    }

    fn bump(&mut self) {
        if self.index + 1 < self.tokens.len() {
            self.index += 1;
        }
    }

    fn expect_eof(&self) -> Result<(), QueryError> {
        let tok = self.current();
        if tok.kind != TokenKind::Eof {
            return Err(QueryError::Parse {
                reason: "trailing input after expression".to_owned(),
                start: tok.span.start,
                end: tok.span.end,
            });
        }
        Ok(())
    }

    fn parse_or(&mut self) -> Result<Expr, QueryError> {
        let mut left = self.parse_and()?;
        while matches!(self.current().kind, TokenKind::Or) {
            let start = left_span(&left).start;
            self.bump();
            let right = self.parse_and()?;
            let end = left_span(&right).end;
            left = Expr::Or {
                left: Box::new(left),
                right: Box::new(right),
                span: Span::new(start, end),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, QueryError> {
        let mut left = self.parse_primary()?;
        while matches!(self.current().kind, TokenKind::And) {
            let start = left_span(&left).start;
            self.bump();
            let right = self.parse_primary()?;
            let end = left_span(&right).end;
            left = Expr::And {
                left: Box::new(left),
                right: Box::new(right),
                span: Span::new(start, end),
            };
        }
        Ok(left)
    }

    fn parse_primary(&mut self) -> Result<Expr, QueryError> {
        let tok = self.current().clone();
        match &tok.kind {
            TokenKind::LParen => {
                self.bump();
                let inner = self.parse_or()?;
                let close = self.current().clone();
                if !matches!(close.kind, TokenKind::RParen) {
                    return Err(QueryError::Parse {
                        reason: "expected ')'".to_owned(),
                        start: close.span.start,
                        end: close.span.end,
                    });
                }
                self.bump();
                Ok(Expr::Group {
                    inner: Box::new(inner),
                    span: Span::new(tok.span.start, close.span.end),
                })
            }
            TokenKind::Ident(name) => {
                let field = Field::parse(name).ok_or_else(|| QueryError::Parse {
                    reason: format!("unknown field `{name}`; allowed: kind, status"),
                    start: tok.span.start,
                    end: tok.span.end,
                })?;
                self.bump();
                let op_tok = self.current().clone();
                let op = match op_tok.kind {
                    TokenKind::Eq => BinaryOp::Eq,
                    TokenKind::Ne => BinaryOp::Ne,
                    _ => {
                        return Err(QueryError::Parse {
                            reason: "expected '=' or '!=' after field".to_owned(),
                            start: op_tok.span.start,
                            end: op_tok.span.end,
                        });
                    }
                };
                self.bump();
                let val_tok = self.current().clone();
                let value = match val_tok.kind {
                    TokenKind::Ident(s) => Literal::Ident(s),
                    TokenKind::String(s) => Literal::String(s),
                    _ => {
                        return Err(QueryError::Parse {
                            reason: "expected identifier or string value".to_owned(),
                            start: val_tok.span.start,
                            end: val_tok.span.end,
                        });
                    }
                };
                self.bump();
                Ok(Expr::Compare {
                    field,
                    op,
                    value,
                    span: Span::new(tok.span.start, val_tok.span.end),
                })
            }
            TokenKind::Eof => Err(QueryError::Parse {
                reason: "empty query".to_owned(),
                start: tok.span.start,
                end: tok.span.end,
            }),
            _ => Err(QueryError::Parse {
                reason: "expected field or '('".to_owned(),
                start: tok.span.start,
                end: tok.span.end,
            }),
        }
    }
}

fn left_span(expr: &Expr) -> Span {
    match expr {
        Expr::Compare { span, .. }
        | Expr::And { span, .. }
        | Expr::Or { span, .. }
        | Expr::Group { span, .. } => *span,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_equality() {
        let expr = parse("kind = threat_actor", &Limits::default()).unwrap();
        assert!(matches!(
            expr,
            Expr::Compare {
                field: Field::Kind,
                op: BinaryOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn rejects_sql_comment() {
        let err = parse("kind = x; drop table", &Limits::default()).unwrap_err();
        assert!(matches!(err, QueryError::Lex { .. }));
    }

    #[test]
    fn rejects_unknown_field() {
        let err = parse("password = secret", &Limits::default()).unwrap_err();
        assert!(matches!(err, QueryError::Parse { .. }));
    }

    #[test]
    fn enforces_token_limit() {
        let mut q = String::from("kind = a");
        for _ in 0..40 {
            q.push_str(" and kind = a");
        }
        let err = parse(&q, &Limits::tight()).unwrap_err();
        assert!(matches!(err, QueryError::Limit { .. }));
    }
}
