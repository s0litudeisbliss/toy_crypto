use std::{collections::HashMap};
struct Document{
    id:usize,
    content:String,
}

struct InvertedIndex{
    indexes:HashMap<String,Vec<usize>>,
    documents:HashMap<usize,Document>,

}

impl InvertedIndex{
    fn new()-> InvertedIndex
    {
        InvertedIndex{
            indexes:HashMap::new(),
            documents:HashMap::new(),
        }
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
}

