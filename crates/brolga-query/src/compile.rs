//! Compile AST → typed storage filters.

use brolga_model::entity::EntityKind;
use brolga_model::status::LifecycleStatus;
use brolga_storage::EntityQuery;

use crate::error::QueryError;
use crate::limits::Limits;
use crate::parse;
use crate::syntax::{BinaryOp, Expr, Field, Literal};

/// Parse and compile a query string to an [`EntityQuery`].
///
/// # Errors
///
/// Lex, parse, limit, or compile failures.
pub fn compile_entity_query(input: &str, limits: &Limits) -> Result<EntityQuery, QueryError> {
    let expr = parse::parse(input, limits)?;
    compile_expr(&expr)
}

fn compile_expr(expr: &Expr) -> Result<EntityQuery, QueryError> {
    match expr {
        Expr::Group { inner, .. } => compile_expr(inner),
        Expr::Compare {
            field, op, value, ..
        } => {
            if *op != BinaryOp::Eq {
                return Err(QueryError::Compile {
                    reason:
                        "only '=' is supported for entity filters in this release; '!=' reserved"
                            .to_owned(),
                });
            }
            let mut query = EntityQuery::unfiltered();
            let text = literal_text(value);
            match field {
                Field::Kind => {
                    let kind = EntityKind::all()
                        .iter()
                        .copied()
                        .find(|k| k.as_str() == text)
                        .ok_or_else(|| QueryError::Compile {
                            reason: format!("unknown entity kind `{text}`"),
                        })?;
                    query = query.with_kind(kind);
                }
                Field::Status => {
                    let status = LifecycleStatus::all()
                        .iter()
                        .copied()
                        .find(|s| s.as_str() == text)
                        .ok_or_else(|| QueryError::Compile {
                            reason: format!("unknown lifecycle status `{text}`"),
                        })?;
                    query = query.with_status(status);
                }
            }
            Ok(query)
        }
        Expr::And { left, right, .. } => {
            let a = compile_expr(left)?;
            let b = compile_expr(right)?;
            Ok(merge_and(a, b))
        }
        Expr::Or { .. } => Err(QueryError::Compile {
            reason: "`or` is not supported for entity filters yet; use separate queries".to_owned(),
        }),
    }
}

fn literal_text(value: &Literal) -> String {
    match value {
        Literal::Ident(s) | Literal::String(s) => s.clone(),
    }
}

fn merge_and(mut a: EntityQuery, b: EntityQuery) -> EntityQuery {
    a.kinds.extend(b.kinds);
    a.statuses.extend(b.statuses);
    if a.last_seen_from.is_none() {
        a.last_seen_from = b.last_seen_from;
    }
    if a.last_seen_before.is_none() {
        a.last_seen_before = b.last_seen_before;
    }
    a
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use brolga_model::entity::EntityKind;
    use brolga_model::status::LifecycleStatus;

    #[test]
    fn compiles_kind_and_status() {
        let q = compile_entity_query(
            "kind = threat_actor and status = active",
            &Limits::default(),
        )
        .unwrap();
        assert!(q.kinds.contains(&EntityKind::ThreatActor));
        assert!(q.statuses.contains(&LifecycleStatus::Active));
    }

    #[test]
    fn rejects_or_for_now() {
        let err = compile_entity_query("kind = a or kind = b", &Limits::default()).unwrap_err();
        assert!(matches!(err, QueryError::Compile { .. }));
    }
}
