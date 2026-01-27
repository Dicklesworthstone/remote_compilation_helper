//! JSON Schema Generation for RCH API Types
//!
//! This module provides schema generation capabilities for API documentation
//! and machine-readable specifications.
//!
//! # Generated Schemas
//!
//! - `api-response.schema.json` - The unified API response envelope
//! - `api-error.schema.json` - Error response structure
//! - `error-codes.json` - Machine-readable error code catalog
//!
//! # Example
//!
//! ```rust
//! use rch_common::api::schema::{generate_api_response_schema, generate_error_catalog};
//!
//! // Generate API response schema
//! let schema = generate_api_response_schema();
//! println!("{}", serde_json::to_string_pretty(&schema).unwrap());
//!
//! // Generate error catalog
//! let catalog = generate_error_catalog();
//! println!("{}", serde_json::to_string_pretty(&catalog).unwrap());
//! ```

use crate::api::response::AnyJson;
use crate::api::{ApiError, ApiResponse};
use crate::errors::catalog::{ErrorCategory, ErrorCode};
use schemars::schema::RootSchema;
use schemars::schema_for;
use serde::{Deserialize, Serialize};

/// Generate JSON Schema for the API response envelope.
///
/// Returns the schema for `ApiResponse<AnyJson>` which represents
/// the generic response envelope where `data` can be any JSON value.
#[must_use]
pub fn generate_api_response_schema() -> RootSchema {
    schema_for!(ApiResponse<AnyJson>)
}

/// Generate JSON Schema for API errors.
#[must_use]
pub fn generate_api_error_schema() -> RootSchema {
    schema_for!(ApiError)
}

/// Machine-readable error code entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCodeEntry {
    /// Error code in RCH-Exxx format.
    pub code: String,
    /// Numeric code (e.g., 100 for RCH-E100).
    pub number: u16,
    /// Error category.
    pub category: ErrorCategory,
    /// Human-readable error message.
    pub message: String,
    /// Remediation steps.
    pub remediation: Vec<String>,
    /// Documentation URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_url: Option<String>,
}

/// Machine-readable error category entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCategoryEntry {
    /// Category identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Category description.
    pub description: String,
    /// Code range (e.g., "001-099").
    pub code_range: String,
}

/// Complete error catalog for machine consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCatalog {
    /// Schema version for catalog format.
    pub schema_version: String,
    /// API version this catalog applies to.
    pub api_version: String,
    /// Error categories with descriptions.
    pub categories: Vec<ErrorCategoryEntry>,
    /// All error codes with full metadata.
    pub errors: Vec<ErrorCodeEntry>,
}

/// Generate the complete error catalog as a structured object.
#[must_use]
pub fn generate_error_catalog() -> ErrorCatalog {
    let categories = vec![
        ErrorCategoryEntry {
            id: "config".to_string(),
            name: ErrorCategory::Config.name().to_string(),
            description: ErrorCategory::Config.description().to_string(),
            code_range: "001-099".to_string(),
        },
        ErrorCategoryEntry {
            id: "network".to_string(),
            name: ErrorCategory::Network.name().to_string(),
            description: ErrorCategory::Network.description().to_string(),
            code_range: "100-199".to_string(),
        },
        ErrorCategoryEntry {
            id: "worker".to_string(),
            name: ErrorCategory::Worker.name().to_string(),
            description: ErrorCategory::Worker.description().to_string(),
            code_range: "200-299".to_string(),
        },
        ErrorCategoryEntry {
            id: "build".to_string(),
            name: ErrorCategory::Build.name().to_string(),
            description: ErrorCategory::Build.description().to_string(),
            code_range: "300-399".to_string(),
        },
        ErrorCategoryEntry {
            id: "transfer".to_string(),
            name: ErrorCategory::Transfer.name().to_string(),
            description: ErrorCategory::Transfer.description().to_string(),
            code_range: "400-499".to_string(),
        },
        ErrorCategoryEntry {
            id: "internal".to_string(),
            name: ErrorCategory::Internal.name().to_string(),
            description: ErrorCategory::Internal.description().to_string(),
            code_range: "500-599".to_string(),
        },
    ];

    let errors: Vec<ErrorCodeEntry> = ErrorCode::all()
        .iter()
        .map(|code| ErrorCodeEntry {
            code: code.code_string(),
            number: code.code_number(),
            category: code.category(),
            message: code.message().to_string(),
            remediation: code
                .remediation()
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            doc_url: code.doc_url().map(String::from),
        })
        .collect();

    ErrorCatalog {
        schema_version: "1.0".to_string(),
        api_version: crate::api::API_VERSION.to_string(),
        categories,
        errors,
    }
}

/// Schema export result containing all generated schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaExportResult {
    /// Number of schema files generated.
    pub files_generated: usize,
    /// List of generated file paths.
    pub files: Vec<String>,
    /// Output directory.
    pub output_dir: String,
}

/// Export all schemas to the specified directory.
///
/// # Arguments
///
/// * `output_dir` - Directory to write schema files to
///
/// # Returns
///
/// Result containing export summary or error.
///
/// # Errors
///
/// Returns error if directory creation or file writing fails.
pub fn export_schemas(output_dir: &std::path::Path) -> std::io::Result<SchemaExportResult> {
    use std::fs;

    // Ensure directory exists
    fs::create_dir_all(output_dir)?;

    let mut files = Vec::new();

    // 1. API Response Schema
    let api_response_schema = generate_api_response_schema();
    let api_response_path = output_dir.join("api-response.schema.json");
    fs::write(
        &api_response_path,
        serde_json::to_string_pretty(&api_response_schema)?,
    )?;
    files.push(api_response_path.display().to_string());

    // 2. API Error Schema
    let api_error_schema = generate_api_error_schema();
    let api_error_path = output_dir.join("api-error.schema.json");
    fs::write(
        &api_error_path,
        serde_json::to_string_pretty(&api_error_schema)?,
    )?;
    files.push(api_error_path.display().to_string());

    // 3. Error Catalog (not a schema, but machine-readable error codes)
    let error_catalog = generate_error_catalog();
    let error_codes_path = output_dir.join("error-codes.json");
    fs::write(
        &error_codes_path,
        serde_json::to_string_pretty(&error_catalog)?,
    )?;
    files.push(error_codes_path.display().to_string());

    Ok(SchemaExportResult {
        files_generated: files.len(),
        files,
        output_dir: output_dir.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_response_schema() {
        let schema = generate_api_response_schema();
        let json = serde_json::to_string(&schema).unwrap();

        // Verify key fields are present
        assert!(json.contains("api_version"));
        assert!(json.contains("success"));
        assert!(json.contains("timestamp"));
    }

    #[test]
    fn test_generate_api_error_schema() {
        let schema = generate_api_error_schema();
        let json = serde_json::to_string(&schema).unwrap();

        // Verify key fields are present
        assert!(json.contains("code"));
        assert!(json.contains("category"));
        assert!(json.contains("message"));
        assert!(json.contains("remediation"));
    }

    #[test]
    fn test_generate_error_catalog() {
        let catalog = generate_error_catalog();

        // Verify catalog structure
        assert_eq!(catalog.schema_version, "1.0");
        assert_eq!(catalog.api_version, crate::api::API_VERSION);
        assert_eq!(catalog.categories.len(), 6);

        // Verify all error codes are present
        assert_eq!(catalog.errors.len(), ErrorCode::all().len());

        // Verify first error (ConfigNotFound)
        let first = &catalog.errors[0];
        assert_eq!(first.code, "RCH-E001");
        assert_eq!(first.number, 1);
        assert_eq!(first.category, ErrorCategory::Config);
        assert!(!first.remediation.is_empty());
    }

    #[test]
    fn test_error_catalog_serialization() {
        let catalog = generate_error_catalog();
        let json = serde_json::to_string_pretty(&catalog).unwrap();

        // Verify JSON structure
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"categories\""));
        assert!(json.contains("\"errors\""));
        assert!(json.contains("RCH-E001"));
        assert!(json.contains("RCH-E100"));
        assert!(json.contains("RCH-E500"));
    }

    #[test]
    fn test_category_entries() {
        let catalog = generate_error_catalog();

        // Verify each category has correct range
        let config_cat = catalog
            .categories
            .iter()
            .find(|c| c.id == "config")
            .unwrap();
        assert_eq!(config_cat.code_range, "001-099");

        let network_cat = catalog
            .categories
            .iter()
            .find(|c| c.id == "network")
            .unwrap();
        assert_eq!(network_cat.code_range, "100-199");

        let internal_cat = catalog
            .categories
            .iter()
            .find(|c| c.id == "internal")
            .unwrap();
        assert_eq!(internal_cat.code_range, "500-599");
    }

    #[test]
    fn test_export_schemas_to_temp_dir() {
        let temp_dir = std::env::temp_dir().join("rch-schema-test");
        let _ = std::fs::remove_dir_all(&temp_dir); // Clean up if exists

        let result = export_schemas(&temp_dir).unwrap();

        assert_eq!(result.files_generated, 3);
        assert!(result.files.iter().any(|f| f.contains("api-response")));
        assert!(result.files.iter().any(|f| f.contains("api-error")));
        assert!(result.files.iter().any(|f| f.contains("error-codes")));

        // Verify files exist and contain valid JSON
        for file in &result.files {
            let content = std::fs::read_to_string(file).unwrap();
            let _: serde_json::Value = serde_json::from_str(&content).unwrap();
        }

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
