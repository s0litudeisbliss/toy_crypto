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
#[derive(Debug, Clone, Default)]
struct EncryptedCipherText {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    associated_data: Vec<u8>,
}
/*
Key = HMAC(Keyword,K1)
Value = Encrypted List of All document IDs containing keyword
*/
#[derive(Debug)]
struct encrypted_inverted_index {
    encrypted_indexes: HashMap<Vec<u8>, EncryptedCipherText>,
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
    fn setup_db(&self, index: &InvertedIndex) -> encrypted_inverted_index {
        let mut encrypted_index = encrypted_inverted_index {
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
            cipher
                .encrypt_in_place(Nonce::from_slice(&nonce), &associated_data, &mut buffer)
                .expect("Encryption failed");

            let ct = EncryptedCipherText {
                nonce,
                ciphertext: buffer,
                associated_data: associated_data,
            };
            encrypted_index
                .encrypted_indexes
                .insert(token_hash.to_vec(), ct);
        }

        encrypted_index
    }
    /*
    Query token is HMAC(K1, w)
    Parameters: K1, K2, Query token
    - Compute Addr_w: F(K1, w) → HMAC-SHA256(K1, w) (Note that this is the same as the query token which is provided to the server)
    - Retrieve Encr_w from DB using Addr_w and pass to client for decryption

    */

    fn query_db(
        &self,
        encrypted_inverted_index: &encrypted_inverted_index,
        query_token: &Vec<Vec<u8>>,
    ) -> Result<EncryptedCipherText, String> {
        if query_token.is_empty() {
            return Err("Query token is empty".to_string());
        }

        let token = &query_token[0];
        if !encrypted_inverted_index
            .encrypted_indexes
            .contains_key(token)
        {
            return Err("Query token not found in encrypted index".to_string());
        }

        encrypted_inverted_index
            .encrypted_indexes
            .get(token)
            .cloned()
            .ok_or_else(|| "Query token not found in encrypted index".to_string())
    }

    fn decrypt_result(
        &self,
        encrypted_doc_ids: EncryptedCipherText,
        token: &str,
    ) -> Result<Vec<u8>, String> {
        // Derive 32-byte key for AES-256 from k2 using HMAC
        let mut key_mac =
            <HmacSha256 as Mac>::new_from_slice(&self.k2).expect("HMAC can take key of any size");

        //Get keywords by tokenizing the query and then use the first token to derive the key for decryption
        let tokens = tokenize(token);
        if tokens.is_empty() {
            return Err("Token is empty".to_string());
        }
        key_mac.update(tokens[0].as_bytes());
        let derived_key = key_mac.finalize().into_bytes();

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived_key));

        let nonce = &encrypted_doc_ids.nonce;

        let mut buffer = encrypted_doc_ids.ciphertext;
        let associated_data: Vec<u8> = encrypted_doc_ids.associated_data;

        cipher
            .decrypt_in_place(
                Nonce::from_slice(&nonce.as_slice()),
                &associated_data,
                &mut buffer,
            )
            .expect("Decryption failed");

        Ok(buffer)
    }

    fn gen_query_token(&self, query: &str) -> Result<Vec<Vec<u8>>, String> {
        let tokens = tokenize(query);
        let mut res = Vec::<Vec<u8>>::new();
        if tokens.is_empty() {
            return Err("Query contains no valid tokens".to_string());
        } else {
            for token in tokens {
                let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.k1)
                    .expect("HMAC can take key of any size");
                mac.update(token.as_bytes()); // Use tokenized (lowercase) keyword
                res.push(mac.finalize().into_bytes().to_vec());
            }
        }
        Ok(res)
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
        assert_eq!(tokens, vec!["hello", "world", "this", "is", "a", "test"]);
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
    #[test]
    fn test_query_db() {
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
        let query_token = params.gen_query_token("Hello");
        let encrypted_result = params
            .query_db(&encrypted_index, &query_token.unwrap())
            .expect("Query token should exist");
        println!("Encrypted result: {:?}", encrypted_result);
        let decrypted_result = params.decrypt_result(encrypted_result, "Hello");
        println!("Decrypted result: {:?}", decrypted_result);
        //assert that decrypted result contains the doc ids 1 and 2
        let doc_ids: Vec<usize> = decrypted_result
            .unwrap()
            .chunks(8)
            .map(|chunk| usize::from_le_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(doc_ids, vec![1, 2]);
    }
}
