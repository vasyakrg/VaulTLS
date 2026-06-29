pub(crate) fn order_identifiers(domain: &str, include_wildcard: bool) -> Vec<String> {
    let base = domain.trim().trim_end_matches('.').to_string();
    if include_wildcard {
        vec![base.clone(), format!("*.{base}")]
    } else {
        vec![base]
    }
}

#[cfg(test)]
mod tests {
    use super::order_identifiers;
    #[test]
    fn single_domain() {
        assert_eq!(order_identifiers("example.com", false), vec!["example.com".to_string()]);
    }
    #[test]
    fn domain_with_wildcard() {
        assert_eq!(
            order_identifiers("example.com", true),
            vec!["example.com".to_string(), "*.example.com".to_string()]
        );
    }
}
