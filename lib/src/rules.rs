use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Action to take when a rule matches
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Allow,
    Deny,
}

/// Parsed destination port filter
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationPortFilter {
    Single(u16),
    Range(u16, u16),
}

impl DestinationPortFilter {
    /// Parse a port filter string like "6881" or "6881-6889"
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some((start_str, end_str)) = s.split_once('-') {
            let start: u16 = start_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range start: '{}'", start_str.trim()))?;
            let end: u16 = end_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port range end: '{}'", end_str.trim()))?;
            if start > end {
                return Err(format!(
                    "Port range start ({}) must be <= end ({})",
                    start, end
                ));
            }
            Ok(DestinationPortFilter::Range(start, end))
        } else {
            let port: u16 = s
                .trim()
                .parse()
                .map_err(|_| format!("Invalid port: '{}'", s.trim()))?;
            Ok(DestinationPortFilter::Single(port))
        }
    }

    /// Check if a port matches this filter
    pub fn matches(&self, port: u16) -> bool {
        match self {
            DestinationPortFilter::Single(p) => port == *p,
            DestinationPortFilter::Range(start, end) => port >= *start && port <= *end,
        }
    }
}

/// Inbound filter rule (evaluated at TLS handshake)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundRule {
    /// CIDR range to match against client IP
    #[serde(default)]
    pub cidr: Option<String>,

    /// Client random prefix to match (hex-encoded)
    /// Can optionally include a mask in format: "prefix[/mask]" (e.g., "aabbcc/ff00ff")
    /// If mask is specified, matching uses: client_random & mask == prefix & mask
    /// If no mask, uses prefix matching
    #[serde(default)]
    pub client_random_prefix: Option<String>,

    /// Action to take when this rule matches
    pub action: RuleAction,
}

/// Outbound filter rule (evaluated per TCP CONNECT / UDP request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundRule {
    /// Destination port or port range to match (e.g. "6881" or "6881-6889")
    pub destination_port: String,

    /// Action to take when this rule matches
    pub action: RuleAction,
}

/// Inbound rules configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundRulesConfig {
    /// Default action when no inbound rules match
    #[serde(default)]
    pub default_action: Option<RuleAction>,

    /// List of inbound filter rules
    #[serde(default)]
    pub rule: Vec<InboundRule>,
}

/// Outbound rules configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutboundRulesConfig {
    /// Default action when no outbound rules match
    #[serde(default)]
    pub default_action: Option<RuleAction>,

    /// List of outbound filter rules
    #[serde(default)]
    pub rule: Vec<OutboundRule>,
}

/// Top-level rules configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    /// Inbound rules (client filtering at TLS handshake)
    #[serde(default)]
    pub inbound: InboundRulesConfig,

    /// Outbound rules (destination filtering per request)
    #[serde(default)]
    pub outbound: OutboundRulesConfig,
}

/// Rule evaluation engine
pub struct RulesEngine {
    rules: RulesConfig,
}

/// Result of rule evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleEvaluation {
    Allow,
    Deny,
}

impl InboundRule {
    /// Check if this rule matches the given connection parameters
    pub fn matches(&self, client_ip: &IpAddr, client_random: Option<&[u8]>) -> bool {
        let mut matches = true;

        // Check CIDR match if specified
        if let Some(cidr_str) = &self.cidr {
            if let Ok(cidr) = cidr_str.parse::<IpNet>() {
                matches &= cidr.contains(client_ip);
            } else {
                // Invalid CIDR, rule doesn't match
                return false;
            }
        }

        // Check client_random prefix if specified
        if let Some(prefix_str) = &self.client_random_prefix {
            if let Some(client_random_data) = client_random {
                // Check if mask is specified in format "prefix[/mask]"
                if let Some(slash_pos) = prefix_str.find('/') {
                    // Parse prefix and mask separately
                    let (prefix_part, mask_part) = prefix_str.split_at(slash_pos);
                    let mask_part = &mask_part[1..]; // Skip the '/'

                    if let (Ok(prefix_bytes), Ok(mask_bytes)) =
                        (hex::decode(prefix_part), hex::decode(mask_part))
                    {
                        // Apply mask: client_random & mask == prefix & mask
                        let mask_len = mask_bytes
                            .len()
                            .min(prefix_bytes.len())
                            .min(client_random_data.len());
                        let mut masked_match = mask_len > 0;

                        for i in 0..mask_len {
                            if (client_random_data[i] & mask_bytes[i])
                                != (prefix_bytes[i] & mask_bytes[i])
                            {
                                masked_match = false;
                                break;
                            }
                        }

                        matches &= masked_match;
                    } else {
                        // Invalid hex in prefix or mask, rule doesn't match
                        return false;
                    }
                } else {
                    // No mask, use simple prefix matching
                    if let Ok(prefix_bytes) = hex::decode(prefix_str) {
                        matches &= client_random_data.starts_with(&prefix_bytes);
                    } else {
                        // Invalid hex prefix, rule doesn't match
                        return false;
                    }
                }
            } else {
                // No client_random provided but rule requires it, doesn't match
                matches = false;
            }
        }

        matches
    }
}

impl OutboundRule {
    /// Check if the given port matches this rule's destination_port filter
    pub fn matches_port(&self, port: u16) -> bool {
        match DestinationPortFilter::parse(&self.destination_port) {
            Ok(filter) => filter.matches(port),
            Err(_) => false, // Invalid filter doesn't match
        }
    }
}

impl RulesEngine {
    /// Create a new rules engine from rules config
    pub fn from_config(rules: RulesConfig) -> Self {
        Self { rules }
    }

    /// Create a default rules engine that allows all connections
    pub fn default_allow() -> Self {
        Self {
            rules: RulesConfig::default(),
        }
    }

    /// Evaluate connection against inbound rules at TLS handshake time.
    /// Returns the action from the first matching rule, or the default action (Allow if unset).
    pub fn evaluate(&self, client_ip: &IpAddr, client_random: Option<&[u8]>) -> RuleEvaluation {
        let inbound = &self.rules.inbound;

        if client_random.is_none()
            && inbound
                .rule
                .iter()
                .any(|r| r.client_random_prefix.is_some())
        {
            return RuleEvaluation::Deny;
        }

        for rule in &inbound.rule {
            if rule.matches(client_ip, client_random) {
                return match rule.action {
                    RuleAction::Allow => RuleEvaluation::Allow,
                    RuleAction::Deny => RuleEvaluation::Deny,
                };
            }
        }

        // Default action from config, or Allow if not specified
        match &inbound.default_action {
            Some(RuleAction::Deny) => RuleEvaluation::Deny,
            _ => RuleEvaluation::Allow,
        }
    }

    /// Evaluate destination port against outbound rules (per TCP CONNECT / UDP request).
    /// Returns the action from the first matching rule, or the default action (Allow if unset).
    pub fn evaluate_destination(&self, port: u16) -> RuleEvaluation {
        let outbound = &self.rules.outbound;

        for rule in &outbound.rule {
            if rule.matches_port(port) {
                return match rule.action {
                    RuleAction::Allow => RuleEvaluation::Allow,
                    RuleAction::Deny => RuleEvaluation::Deny,
                };
            }
        }

        // Default action from config, or Allow if not specified
        match &outbound.default_action {
            Some(RuleAction::Deny) => RuleEvaluation::Deny,
            _ => RuleEvaluation::Allow,
        }
    }

    /// Get a reference to the rules configuration
    pub fn config(&self) -> &RulesConfig {
        &self.rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_cidr_rule_matching() {
        let rule = InboundRule {
            cidr: Some("192.168.1.0/24".to_string()),
            client_random_prefix: None,
            action: RuleAction::Allow,
        };

        let ip_match = IpAddr::from_str("192.168.1.100").unwrap();
        let ip_no_match = IpAddr::from_str("10.0.0.1").unwrap();

        assert!(rule.matches(&ip_match, None));
        assert!(!rule.matches(&ip_no_match, None));
    }

    #[test]
    fn test_client_random_prefix_matching() {
        let rule = InboundRule {
            cidr: None,
            client_random_prefix: Some("aabbcc".to_string()),
            action: RuleAction::Deny,
        };

        let client_random_match = hex::decode("aabbccddee").unwrap();
        let client_random_no_match = hex::decode("112233").unwrap();

        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        assert!(rule.matches(&ip, Some(&client_random_match)));
        assert!(!rule.matches(&ip, Some(&client_random_no_match)));
        assert!(!rule.matches(&ip, None)); // No client random provided
    }

    #[test]
    fn test_combined_rule_matching() {
        let rule = InboundRule {
            cidr: Some("10.0.0.0/8".to_string()),
            client_random_prefix: Some("ff".to_string()),
            action: RuleAction::Allow,
        };

        let ip_match = IpAddr::from_str("10.1.2.3").unwrap();
        let ip_no_match = IpAddr::from_str("192.168.1.1").unwrap();
        let client_random_match = hex::decode("ff00112233").unwrap();
        let client_random_no_match = hex::decode("0011223344").unwrap();

        // Both must match
        assert!(rule.matches(&ip_match, Some(&client_random_match)));
        assert!(!rule.matches(&ip_match, Some(&client_random_no_match)));
        assert!(!rule.matches(&ip_no_match, Some(&client_random_match)));
        assert!(!rule.matches(&ip_no_match, Some(&client_random_no_match)));
    }

    #[test]
    fn test_rules_engine_evaluation() {
        let rules = RulesConfig {
            inbound: InboundRulesConfig {
                default_action: Some(RuleAction::Deny),
                rule: vec![
                    InboundRule {
                        cidr: Some("192.168.1.0/24".to_string()),
                        client_random_prefix: None,
                        action: RuleAction::Deny,
                    },
                    InboundRule {
                        cidr: Some("10.0.0.0/8".to_string()),
                        client_random_prefix: None,
                        action: RuleAction::Allow,
                    },
                ],
            },
            outbound: OutboundRulesConfig::default(),
        };

        let engine = RulesEngine::from_config(rules);

        let ip_deny = IpAddr::from_str("192.168.1.100").unwrap();
        let ip_allow = IpAddr::from_str("10.1.2.3").unwrap();
        let ip_default = IpAddr::from_str("172.16.1.1").unwrap();

        assert_eq!(engine.evaluate(&ip_deny, None), RuleEvaluation::Deny);
        assert_eq!(engine.evaluate(&ip_allow, None), RuleEvaluation::Allow);
        assert_eq!(engine.evaluate(&ip_default, None), RuleEvaluation::Deny); // Default deny
    }

    #[test]
    fn test_rules_engine_fails_closed_without_client_random() {
        let rules = RulesConfig {
            inbound: InboundRulesConfig {
                default_action: None,
                rule: vec![InboundRule {
                    cidr: None,
                    client_random_prefix: Some("aabbcc".to_string()),
                    action: RuleAction::Allow,
                }],
            },
            outbound: OutboundRulesConfig::default(),
        };

        let engine = RulesEngine::from_config(rules);
        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        assert_eq!(engine.evaluate(&ip, None), RuleEvaluation::Deny);
    }

    #[test]
    fn test_client_random_mask_matching() {
        let rule = InboundRule {
            cidr: None,
            client_random_prefix: Some("a0b0/f0f0".to_string()),
            action: RuleAction::Allow,
        };

        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        let client_random_match1 = hex::decode("a5b5ccdd").unwrap();
        let client_random_match2 = hex::decode("a9bfeeaa").unwrap();
        let client_random_no_match1 = hex::decode("b0b01122").unwrap();
        let client_random_no_match2 = hex::decode("a0c03344").unwrap();

        assert!(rule.matches(&ip, Some(&client_random_match1)));
        assert!(rule.matches(&ip, Some(&client_random_match2)));
        assert!(!rule.matches(&ip, Some(&client_random_no_match1)));
        assert!(!rule.matches(&ip, Some(&client_random_no_match2)));
    }

    #[test]
    fn test_client_random_mask_full_bytes() {
        let rule = InboundRule {
            cidr: None,
            client_random_prefix: Some("12345678/ffff0000".to_string()),
            action: RuleAction::Allow,
        };

        let ip = IpAddr::from_str("127.0.0.1").unwrap();

        let client_random_match = hex::decode("1234aaaabbbb").unwrap();
        let client_random_no_match = hex::decode("12335678ccdd").unwrap();

        assert!(rule.matches(&ip, Some(&client_random_match)));
        assert!(!rule.matches(&ip, Some(&client_random_no_match)));
    }

    #[test]
    fn test_client_random_invalid_mask_format() {
        let rule = InboundRule {
            cidr: None,
            client_random_prefix: Some("aabbcc/".to_string()),
            action: RuleAction::Allow,
        };

        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        let client_random = hex::decode("aabbccddee").unwrap();

        assert!(!rule.matches(&ip, Some(&client_random)));
    }

    #[test]
    fn test_destination_port_single_rule_matching() {
        let rule = OutboundRule {
            destination_port: "6969".to_string(),
            action: RuleAction::Deny,
        };

        assert!(rule.matches_port(6969));
        assert!(!rule.matches_port(6968));
        assert!(!rule.matches_port(80));
    }

    #[test]
    fn test_destination_port_range_rule_matching() {
        let rule = OutboundRule {
            destination_port: "6881-6889".to_string(),
            action: RuleAction::Deny,
        };

        assert!(rule.matches_port(6881));
        assert!(rule.matches_port(6885));
        assert!(rule.matches_port(6889));
        assert!(!rule.matches_port(6880));
        assert!(!rule.matches_port(6890));
        assert!(!rule.matches_port(443));
    }

    #[test]
    fn test_destination_port_invalid_rule_matching() {
        let rule_text = OutboundRule {
            destination_port: "abc".to_string(),
            action: RuleAction::Deny,
        };
        assert!(!rule_text.matches_port(80));

        let rule_reversed = OutboundRule {
            destination_port: "6889-6881".to_string(),
            action: RuleAction::Deny,
        };
        assert!(!rule_reversed.matches_port(6885));

        let rule_empty = OutboundRule {
            destination_port: "".to_string(),
            action: RuleAction::Deny,
        };
        assert!(!rule_empty.matches_port(80));
    }

    #[test]
    fn test_evaluate_destination() {
        let rules = RulesConfig {
            inbound: InboundRulesConfig::default(),
            outbound: OutboundRulesConfig {
                default_action: None,
                rule: vec![
                    OutboundRule {
                        destination_port: "6881-6889".to_string(),
                        action: RuleAction::Deny,
                    },
                    OutboundRule {
                        destination_port: "6969".to_string(),
                        action: RuleAction::Deny,
                    },
                ],
            },
        };

        let engine = RulesEngine::from_config(rules);

        assert_eq!(engine.evaluate_destination(6881), RuleEvaluation::Deny);
        assert_eq!(engine.evaluate_destination(6885), RuleEvaluation::Deny);
        assert_eq!(engine.evaluate_destination(6969), RuleEvaluation::Deny);
        assert_eq!(engine.evaluate_destination(80), RuleEvaluation::Allow);
        assert_eq!(engine.evaluate_destination(443), RuleEvaluation::Allow);
    }

    #[test]
    fn test_inbound_outbound_independent_defaults() {
        let rules = RulesConfig {
            inbound: InboundRulesConfig {
                default_action: Some(RuleAction::Deny),
                rule: vec![InboundRule {
                    cidr: Some("10.0.0.0/8".to_string()),
                    client_random_prefix: None,
                    action: RuleAction::Allow,
                }],
            },
            outbound: OutboundRulesConfig {
                default_action: Some(RuleAction::Allow),
                rule: vec![OutboundRule {
                    destination_port: "6881-6889".to_string(),
                    action: RuleAction::Deny,
                }],
            },
        };

        let engine = RulesEngine::from_config(rules);

        // Inbound: allowed subnet passes
        let ip_allow = IpAddr::from_str("10.1.2.3").unwrap();
        assert_eq!(engine.evaluate(&ip_allow, None), RuleEvaluation::Allow);

        // Inbound: unknown subnet hits default deny
        let ip_deny = IpAddr::from_str("172.16.1.1").unwrap();
        assert_eq!(engine.evaluate(&ip_deny, None), RuleEvaluation::Deny);

        // Outbound: torrent port blocked
        assert_eq!(engine.evaluate_destination(6881), RuleEvaluation::Deny);

        // Outbound: normal port uses default allow
        assert_eq!(engine.evaluate_destination(443), RuleEvaluation::Allow);
    }

    #[test]
    fn test_inbound_deny_does_not_affect_outbound() {
        // This is the key test for the PR feedback:
        // inbound default=deny should NOT affect outbound evaluation
        let rules = RulesConfig {
            inbound: InboundRulesConfig {
                default_action: Some(RuleAction::Deny),
                rule: vec![InboundRule {
                    cidr: None,
                    client_random_prefix: Some("aabbcc".to_string()),
                    action: RuleAction::Allow,
                }],
            },
            outbound: OutboundRulesConfig {
                default_action: None, // defaults to Allow
                rule: vec![],
            },
        };

        let engine = RulesEngine::from_config(rules);

        // Inbound: no client_random → deny
        let ip = IpAddr::from_str("1.2.3.4").unwrap();
        assert_eq!(engine.evaluate(&ip, None), RuleEvaluation::Deny);

        // Outbound: should still allow everything — inbound deny doesn't leak
        assert_eq!(engine.evaluate_destination(80), RuleEvaluation::Allow);
        assert_eq!(engine.evaluate_destination(443), RuleEvaluation::Allow);
        assert_eq!(engine.evaluate_destination(6881), RuleEvaluation::Allow);
    }
}
