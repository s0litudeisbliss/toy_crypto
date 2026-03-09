use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    AeadInPlace, Aes256Gcm, Key, Nonce,
};
use hex_literal::hex;
use hmac::{Hmac, Mac};
use rand::{rngs::StdRng, Rng, RngExt};
use sha2::Sha256;
use std::collections::HashMap;

struct Document {
    id: usize,
    content: String,
}

struct InvertedIndex {
    indexes: HashMap<String, Vec<usize>>,
    documents: HashMap<usize, Document>,
}
/*
Key = HMAC(Keyword,K1)
Value = Encrypted List of All document IDs containing keyword
*/
#[derive(Debug)]
struct EncryptedInveretedIndex {
    encrypted_indexes: HashMap<Vec<u8>, Vec<u8>>,
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

type HmacSha256 = Hmac<Sha256>;

struct SseParams {
    k1: [u8; 16],
    k2: [u8; 16],
}

impl SseParams {
    fn init_params(&mut self) {
        let mut rng: StdRng = rand::make_rng();
        rng.fill_bytes(&mut self.k1);
        rng.fill_bytes(&mut self.k2);
    }

    /*
    - Compute Addr_w: F(K1, w) → HMAC-SHA256(K1, w)
    - Compute Encr_w: AES-GCM(iv = random, key = K2, plaintext = doc_ids)
    - Store

     */
    fn setup_db(&self, index: &InvertedIndex) -> EncryptedInveretedIndex {
        let mut encrypted_index = EncryptedInveretedIndex {
            encrypted_indexes: HashMap::new(),
        };

        for (token, doc_ids) in &index.indexes {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.k1)
                .expect("HMAC can take key of any size");

            mac.update(token.as_bytes());
            let token_hash = mac.finalize().into_bytes();

            //Encrypt each docid with AES-GCM ( key = HMAC(K2,w) , Message = DocID, iv = Random
            let mut rng: StdRng = rand::make_rng();
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);

            // Derive 32-byte key for AES-256 from k2 using HMAC
            let mut key_mac = <HmacSha256 as Mac>::new_from_slice(&self.k2)
                .expect("HMAC can take key of any size");
            key_mac.update(token.as_bytes());
            let derived_key = key_mac.finalize().into_bytes();

            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));
            let mut buffer: Vec<u8> = Vec::new();
            buffer.extend_from_slice(
                doc_ids
                    .as_slice()
                    .iter()
                    .flat_map(|id| id.to_le_bytes())
                    .collect::<Vec<u8>>()
                    .as_slice(),
            );
            let associated_data: Vec<u8> = Vec::new();
            cipher.encrypt_in_place(Nonce::from_slice(&nonce), &associated_data, &mut buffer);

            encrypted_index
                .encrypted_indexes
                .insert(token_hash.to_vec(), buffer.to_vec());
        }

        encrypted_index
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

#[cfg(test)]
mod sse_tests {
    use super::*;

    #[test]
    fn test_setup_db() {
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

        let mut params = SseParams {
            k1: [0u8; 16],
            k2: [0u8; 16],
        };
        params.init_params();

        let encrypted_index = params.setup_db(&index);
        println!("Encrypted index: {:?}", encrypted_index);
    }
}
