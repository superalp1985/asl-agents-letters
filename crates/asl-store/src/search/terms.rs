use std::sync::LazyLock;

use asl_types::{error::AslError, protocol::ConceptRef};
use jieba_rs::Jieba;

const MAX_QUERY_BYTES: usize = 4096;
const MAX_QUERY_TERMS: usize = 64;
const MAX_RESOURCE_TOPICS: usize = 16;
const MAX_QUERY_TOPICS: usize = 64;

static JIEBA: LazyLock<Jieba> = LazyLock::new(Jieba::new);

enum TextMode {
    Index,
    Query,
}

fn is_ideograph(c: char) -> bool {
    matches!(c, '\u{3400}'..='\u{4dbf}' | '\u{4e00}'..='\u{9fff}' | '\u{f900}'..='\u{faff}'
        | '\u{20000}'..='\u{2ffff}' | '\u{30000}'..='\u{3ffff}')
}

fn text_terms(input: &str, mode: TextMode) -> Vec<&str> {
    let mut terms = Vec::new();
    for mut run in input.split(|c: char| !c.is_alphanumeric()) {
        while let Some(first) = run.chars().next() {
            let han = is_ideograph(first);
            let end = run.find(|c| is_ideograph(c) != han).unwrap_or(run.len());
            let (word, rest) = run.split_at(end);
            if han {
                // Index subwords for recall; do not require overlapping subwords in a query.
                let segments = match mode {
                    TextMode::Index => JIEBA.cut_for_search(word, false),
                    TextMode::Query => JIEBA.cut(word, false),
                };
                terms.extend(segments.into_iter().map(|token| token.word));
            } else {
                terms.push(word);
            }
            run = rest;
        }
    }
    terms
}

/// Index text is already byte-bounded by the caller. Store words, not MATCH syntax.
pub(super) fn tokens(input: &str) -> String {
    text_terms(input, TextMode::Index).join(" ")
}

enum Operator {
    And,
    Or,
}

// The parent binds this expression and chooses its columns. Only this builder emits operators.
fn expression<T: AsRef<str>>(operator: Operator, terms: &[T]) -> Option<String> {
    if terms.is_empty() {
        return None;
    }
    let separator = match operator {
        Operator::And => " AND ",
        Operator::Or => " OR ",
    };
    let mut expr = String::new();
    for term in terms {
        if !expr.is_empty() {
            expr.push_str(separator);
        }
        expr.push('"');
        for c in term.as_ref().chars() {
            if c == '"' {
                expr.push('"');
            }
            expr.push(c);
        }
        expr.push('"');
    }
    Some(expr)
}

pub(super) fn text_query(input: &str) -> Result<Option<String>, AslError> {
    if input.len() > MAX_QUERY_BYTES || input.contains('\0') {
        return Err(AslError::InvalidMessage);
    }
    let terms = text_terms(input, TextMode::Query);
    if terms.len() > MAX_QUERY_TERMS {
        return Err(AslError::InvalidMessage);
    }
    Ok(expression(Operator::And, &terms))
}

fn topic_terms(concepts: &[ConceptRef], limit: usize) -> Result<Vec<String>, AslError> {
    if concepts.len() > limit {
        return Err(AslError::InvalidMessage);
    }
    let mut tags = Vec::with_capacity(concepts.len());
    for (i, topic) in concepts.iter().enumerate() {
        // Frozen ASL/1 topic rows in specs/vocabulary-v1.csv, not intents or predicates.
        if !topic.is_topic() || concepts[..i].contains(topic) {
            return Err(AslError::InvalidMessage);
        }
        tags.push(format!("v{}c{}", topic.vocabulary_id, topic.concept_id));
    }
    Ok(tags)
}

pub(super) fn concept_query(concepts: &[ConceptRef]) -> Result<Option<String>, AslError> {
    Ok(expression(
        Operator::Or,
        &topic_terms(concepts, MAX_QUERY_TOPICS)?,
    ))
}

pub(super) fn concept_tokens(concepts: &[ConceptRef]) -> Result<String, AslError> {
    Ok(topic_terms(concepts, MAX_RESOURCE_TOPICS)?.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn topic(id: u32) -> ConceptRef {
        ConceptRef {
            vocabulary_id: 1,
            concept_id: id,
        }
    }

    fn hits(db: &Connection, query: &str) -> Vec<i64> {
        db.prepare("SELECT rowid FROM resource_fts WHERE resource_fts MATCH ?1 ORDER BY rowid")
            .unwrap()
            .query_map([query], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn index() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE VIRTUAL TABLE resource_fts USING fts5(
                title_tokens, summary_tokens, body_tokens, tag_tokens, tokenize='unicode61')",
        )
        .unwrap();
        db
    }

    #[test]
    fn indexes_chinese_and_keeps_fts_operators_literal() {
        let db = index();
        for text in [
            "研究密码安全 Rust OR SQLite",
            "Rust",
            "SQLite",
            "Rust OR SQLiteExtra",
            "Rust SQLite",
        ] {
            db.execute(
                "INSERT INTO resource_fts(body_tokens) VALUES (?1)",
                [tokens(text)],
            )
            .unwrap();
        }
        for query in ["密码", "Rust \"OR\" SQLite*", "(Rust OR SQLite)"] {
            assert_eq!(hits(&db, &text_query(query).unwrap().unwrap()), [1]);
        }
        for query in [
            "NOT",
            "NEAR(Rust SQLite)",
            "body_tokens:Rust",
            "' OR 1=1 --",
        ] {
            assert!(hits(&db, &text_query(query).unwrap().unwrap()).is_empty());
        }
        assert_eq!(text_query("*:'()?!\"").unwrap(), None);
        assert!(text_query("Rust\0OR").is_err());
    }

    #[test]
    fn quotes_each_term_and_escapes_embedded_quotes() {
        assert_eq!(
            expression(Operator::And, &["OR", "a\"b"]).as_deref(),
            Some("\"OR\" AND \"a\"\"b\"")
        );
        let topics = concept_query(&[topic(100), topic(111)]).unwrap();
        assert_eq!(topics.as_deref(), Some("\"v1c100\" OR \"v1c111\""));
    }

    #[test]
    fn text_limits_reject_instead_of_dropping_terms() {
        assert!(text_query(&" ".repeat(MAX_QUERY_BYTES)).unwrap().is_none());
        assert!(text_query(&" ".repeat(MAX_QUERY_BYTES + 1)).is_err());
        assert!(text_query(&"a ".repeat(MAX_QUERY_TERMS)).unwrap().is_some());
        assert!(text_query(&"a ".repeat(MAX_QUERY_TERMS + 1)).is_err());
    }

    #[test]
    fn only_explicit_tags_match_any_requested_topic() {
        let db = index();
        for id in [100, 111, 101] {
            db.execute(
                "INSERT INTO resource_fts(tag_tokens) VALUES (?1)",
                [concept_tokens(&[topic(id)]).unwrap()],
            )
            .unwrap();
        }
        let tag = concept_tokens(&[topic(100)]).unwrap();
        db.execute("INSERT INTO resource_fts(body_tokens) VALUES (?1)", [&tag])
            .unwrap();
        let query = concept_query(&[topic(100), topic(111)]).unwrap().unwrap();
        assert_eq!(hits(&db, &format!("tag_tokens : ({query})")), [1, 2]);
        let text = text_query(&tag).unwrap().unwrap();
        assert_eq!(hits(&db, &format!("body_tokens : ({text})")), [4]);
    }

    #[test]
    fn rejects_invalid_topic_lists_for_index_and_query() {
        assert_eq!(concept_query(&[]).unwrap(), None);
        assert_eq!(concept_tokens(&[]).unwrap(), "");
        for bad in [
            topic(1),
            topic(99),
            topic(112),
            topic(200),
            ConceptRef {
                vocabulary_id: 2,
                concept_id: 100,
            },
        ] {
            assert!(concept_query(&[topic(101), bad]).is_err());
            assert!(concept_tokens(&[topic(101), bad]).is_err());
        }
        for bad in [vec![topic(100); 2], vec![topic(100); 65]] {
            assert!(concept_query(&bad).is_err());
            assert!(concept_tokens(&bad).is_err());
        }
    }
}
