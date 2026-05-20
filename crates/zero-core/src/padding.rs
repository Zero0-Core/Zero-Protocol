/// Pads the data to a specified boundary (e.g., 64 bytes) to prevent traffic analysis.
pub fn pad_to_boundary(data: &mut Vec<u8>, boundary: usize) {
    let padding = (boundary - (data.len() % boundary)) % boundary;
    data.extend(std::iter::repeat(0u8).take(padding));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        let mut data = vec![1, 2, 3]; // 3 bytes
        pad_to_boundary(&mut data, 64);
        assert_eq!(data.len(), 64);

        let mut data2 = vec![0; 64];
        pad_to_boundary(&mut data2, 64);
        assert_eq!(data2.len(), 64); // No padding needed if already on boundary
    }
}
