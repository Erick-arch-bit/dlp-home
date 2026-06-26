use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub description: String,
    pub severity: String,
    pub regex: String,
    #[serde(skip)]
    pub compiled: Option<Regex>,
}

#[derive(Debug, Clone)]
pub struct Scanner {
    patterns: Vec<Pattern>,
    compiled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanMatch {
    pub pattern_name: String,
    pub description: String,
    pub severity: String,
    pub line: usize,
    pub context: String,
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            patterns: default_patterns(),
            compiled: false,
        }
    }

    pub fn compile(&mut self) {
        for p in &mut self.patterns {
            if let Ok(re) = Regex::new(&p.regex) {
                p.compiled = Some(re);
            }
        }
        self.compiled = true;
    }

    pub fn scan_text(&self, content: &str) -> Vec<ScanMatch> {
        if !self.compiled {
            return vec![];
        }

        let mut results = vec![];
        for pattern in &self.patterns {
            if let Some(ref re) = pattern.compiled {
                for m in re.find_iter(content) {
                    let line = content[..m.start()].lines().count().saturating_add(1);
                    let start = m.start().saturating_sub(40);
                    let end = (m.end() + 40).min(content.len());
                    let context = if start < m.start() {
                        format!("...{}...", &content[start..end])
                    } else {
                        format!("{}...", &content[m.start()..end])
                    };

                    results.push(ScanMatch {
                        pattern_name: pattern.name.clone(),
                        description: pattern.description.clone(),
                        severity: pattern.severity.clone(),
                        line,
                        context,
                    });
                }
            }
        }
        results
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Vec<ScanMatch> {
        let content = String::from_utf8_lossy(data);
        self.scan_text(&content)
    }

    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }
}

fn default_patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "credit_card".into(),
            description: "Número de tarjeta de crédito".into(),
            severity: "high".into(),
            regex: r"\b(?:\d[ -]*?){13,19}\b".into(),
            compiled: None,
        },
        Pattern {
            name: "ssn".into(),
            description: "Número de seguro social (EEUU)".into(),
            severity: "critical".into(),
            regex: r"\b\d{3}-\d{2}-\d{4}\b".into(),
            compiled: None,
        },
        Pattern {
            name: "email".into(),
            description: "Dirección de correo electrónico".into(),
            severity: "low".into(),
            regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".into(),
            compiled: None,
        },
        Pattern {
            name: "api_key".into(),
            description: "API key o token".into(),
            severity: "high".into(),
            regex: r#"(?i)(?:api[_-]?key|apikey|secret|token|bearer)\s*[:=]\s*['"]?[A-Za-z0-9_\-=]{16,64}['"]?"#.into(),
            compiled: None,
        },
        Pattern {
            name: "private_key".into(),
            description: "Llave privada RSA/DSA/EC".into(),
            severity: "critical".into(),
            regex: r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----".into(),
            compiled: None,
        },
        Pattern {
            name: "password".into(),
            description: "Posible contraseña en texto plano".into(),
            severity: "high".into(),
            regex: r"(?i)(?:password|passwd|pwd|contraseña)\s*[:=]\s*\S{6,}".into(),
            compiled: None,
        },
        Pattern {
            name: "connection_string".into(),
            description: "Cadena de conexión a base de datos".into(),
            severity: "critical".into(),
            regex: r"(?i)(?:postgres(?:ql)?|mysql|mongodb|redis|sqlite)://\S+:\S+@".into(),
            compiled: None,
        },
        Pattern {
            name: "ip_address".into(),
            description: "Dirección IP interna".into(),
            severity: "low".into(),
            regex: r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b".into(),
            compiled: None,
        },
        Pattern {
            name: "jwt_token".into(),
            description: "Token JWT".into(),
            severity: "high".into(),
            regex: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}".into(),
            compiled: None,
        },
        Pattern {
            name: "aws_key".into(),
            description: "AWS Access Key".into(),
            severity: "critical".into(),
            regex: r"(?i)AKIA[0-9A-Z]{16}".into(),
            compiled: None,
        },
        Pattern {
            name: "github_token".into(),
            description: "Token de GitHub".into(),
            severity: "critical".into(),
            regex: r"(?i)gh[ps]_[A-Za-z0-9]{36,}".into(),
            compiled: None,
        },
        Pattern {
            name: "phone_mx".into(),
            description: "Número telefónico México".into(),
            severity: "medium".into(),
            regex: r"\b(?:52)?(?:\d{2}[-\s]?)?\d{4}[-\s]?\d{4}\b".into(),
            compiled: None,
        },
        Pattern {
            name: "curp".into(),
            description: "CURP (México)".into(),
            severity: "high".into(),
            regex: r"\b[A-Z]{4}\d{6}[H,M][A-Z]{5}[0-9A-Z]\d\b".into(),
            compiled: None,
        },
        Pattern {
            name: "rfc".into(),
            description: "RFC (México)".into(),
            severity: "high".into(),
            regex: r"\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{2,3}\b".into(),
            compiled: None,
        },
    ]
}
