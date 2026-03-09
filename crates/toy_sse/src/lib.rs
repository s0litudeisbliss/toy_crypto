use std::{collections::HashMap};
struct Document{
    id:usize,
    content:String,
}

struct InvertedIndex{
    Indexes:HashMap<String,Vec<usize>>,
    documents:HashMap<usize,Document>,

}

impl InvertedIndex{
    fn new()-> InvertedIndex
    {
        InvertedIndex{
            Indexes:HashMap::new(),
            documents:HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let test_index = InvertedIndex::new(); 
        
    }
}

