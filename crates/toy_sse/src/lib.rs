use std::collections::HashMap;
struct Document {
    id: usize,
    content: String,
}

struct InvertedIndex {
    indexes: HashMap<String, Vec<usize>>,
    documents: HashMap<usize, Document>,
}

impl InvertedIndex {
    fn new() -> InvertedIndex {
        InvertedIndex {
            indexes: HashMap::new(),
            documents: HashMap::new(),
        }
    }

    fn add(&mut self, document: Document) {
        let doc_id = document.id;
        self.documents.insert(doc_id, document);
        for token in tokenize(&self.documents[&doc_id].content) {
            self.indexes.entry(token).or_insert(Vec::new()).push(doc_id);
        }
    }

    fn query(&self, query: &str) -> Vec<usize> {
        let tokens = tokenize(query);
        if tokens.is_empty() {
            return Vec::new();
        }

        // Start with docs matching the first token
        let mut results: Option<Vec<usize>> = None;

        for token in tokens {
            if let Some(doc_ids) = self.indexes.get(&token) {
                match &mut results {
                    None => results = Some(doc_ids.clone()),
                    Some(r) => r.retain(|id| doc_ids.contains(id)), // intersect
                }
            } else {
                // Token not found → no docs can match all tokens
                return Vec::new();
            }
        }

        let mut result = results.unwrap_or_default();
        result.sort();
        result.dedup();
        result
    }
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let test_index = InvertedIndex::new();
    }
    #[test]
    fn test_tokenize() {
        let text = "Hello world! This is a test.";
        let tokens = tokenize(text);
        assert_eq!(tokens, vec!["hello", "world!", "this", "is", "a", "test"]);
    }
    #[test]
    fn test_tokenize_empty() {
        let text = "";

        let tokens = tokenize(text);

        assert_eq!(tokens, Vec::<String>::new());

        println!("Tokens {:?}", tokens);
    }
    #[test]
    fn test_add() {
        let mut index = InvertedIndex::new();
        let doc1 = Document {
            id: 1,
            content: "Hello world".to_string(),
        };
        let doc2 = Document {
            id: 2,
            content: "Hello Rust".to_string(),
        };
        index.add(doc1);
        index.add(doc2);
        assert_eq!(index.query("Hello"), vec![1, 2]);
        assert_eq!(index.query("world"), vec![1]);
        assert_eq!(index.query("Rust"), vec![2]);
    }
    #[test]
    fn test_search() {
        let mut index = InvertedIndex::new();
        let doc1 = Document {
            id: 1,
            content: "Hello world".to_string(),
        };
        let doc2 = Document {
            id: 2,
            content: "Hello Rust".to_string(),
        };
        index.add(doc1);
        index.add(doc2);
        assert_eq!(index.query("Hello"), vec![1, 2]);
        assert_eq!(index.query("world"), vec![1]);
        assert_eq!(index.query("Rust"), vec![2]);
    }

    #[test]
    fn test_search_and_add() {
        let mut index = InvertedIndex::new();
        let doc1 = Document {
            id: 1,
            content: "Hello world".to_string(),
        };
        index.add(doc1);

        assert_eq!(index.query("Hello"), vec![1]);
        let doc2 = Document {
            id: 2,
            content: "Hello Rust".to_string(),
        };
        index.add(doc2);
        assert_eq!(index.query("Hello"), vec![1, 2]);
    }

    #[test]
    fn test_search_multiple_tokens() {
        let mut index = InvertedIndex::new();
        let doc1 = Document {
            id: 1,
            content: "Hello world is mine and I added a random word just for **** and giggles."
                .to_string(),
        };
        let doc2 = Document {
            id: 2,
            content: "Hello Rust is mine and I added a random word just for **** and giggles."
                .to_string(),
        };
        index.add(doc1);
        index.add(doc2);
        assert_eq!(index.query("mine"), vec![1, 2]);
        assert_eq!(index.query("Rust"), vec![2]);
        assert_eq!(index.query("Hello Rust"), vec![2]);
        assert_eq!(index.query("Hello is mine"), vec![1, 2]);
    }
}
