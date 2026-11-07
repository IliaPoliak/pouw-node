use super::{ConfigError, LightConfig, Reason, var};

fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn an_empty_environment_gives_the_defaults() {
    let config = LightConfig::from_vars(vars(&[])).unwrap();
    assert_eq!(config.api_addr, "[::]:8000".parse().unwrap());
    assert_eq!(config.full_nodes, Vec::<String>::new());
}

#[test]
fn the_variables_are_read() {
    let config = LightConfig::from_vars(vars(&[
        (var::API_ADDR, "127.0.0.1:8100"),
        (var::FULL_NODES, "http://node-1:8000, https://node-2:8000/"),
    ]))
    .unwrap();
    assert_eq!(config.api_addr, "127.0.0.1:8100".parse().unwrap());
    assert_eq!(
        config.full_nodes,
        ["http://node-1:8000", "https://node-2:8000"]
    );
}

#[test]
fn variables_of_other_programs_are_ignored() {
    assert!(LightConfig::from_vars(vars(&[("PATH", "/bin"), ("RUST_LOG", "debug")])).is_ok());
}

#[test]
fn an_unknown_pouw_variable_is_an_error() {
    assert_eq!(
        LightConfig::from_vars(vars(&[("POUW_FULL_NODE", "http://a:1")])),
        Err(ConfigError::Unknown("POUW_FULL_NODE".to_owned()))
    );
}

#[test]
fn a_bad_address_is_an_error_naming_the_variable() {
    let error = LightConfig::from_vars(vars(&[(var::API_ADDR, "localhost")])).unwrap_err();
    assert!(matches!(
        error,
        ConfigError::Invalid {
            var: var::API_ADDR,
            reason: Reason::Socket(_),
            ..
        }
    ));
}

#[test]
fn a_full_node_must_be_a_base_url() {
    for bad in [
        "node-1:8000",
        "ftp://node-1",
        "http://",
        "http://node-1/v1",
        "http://a b",
    ] {
        let error = LightConfig::from_vars(vars(&[(var::FULL_NODES, bad)])).unwrap_err();
        assert!(
            matches!(
                error,
                ConfigError::Invalid {
                    var: var::FULL_NODES,
                    reason: Reason::Url(_),
                    ..
                }
            ),
            "{bad}"
        );
    }
}
