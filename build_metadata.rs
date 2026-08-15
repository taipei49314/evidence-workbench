#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedBuildMetadata {
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub dirty: Option<bool>,
    pub tag: Option<String>,
}

pub fn validate(
    commit: Option<String>,
    tree: Option<String>,
    dirty: Option<String>,
    tag: Option<String>,
) -> Result<ValidatedBuildMetadata, String> {
    let any_reported = commit.is_some() || tree.is_some() || dirty.is_some() || tag.is_some();
    if !any_reported {
        return Ok(ValidatedBuildMetadata {
            commit: None,
            tree: None,
            dirty: None,
            tag: None,
        });
    }

    let commit = commit.ok_or_else(|| {
        "EWB_BUILD_VCS_COMMIT is required when VCS build metadata is reported".to_owned()
    })?;
    let tree = tree.ok_or_else(|| {
        "EWB_BUILD_VCS_TREE is required when VCS build metadata is reported".to_owned()
    })?;
    let dirty = dirty.ok_or_else(|| {
        "EWB_BUILD_VCS_DIRTY is required when VCS build metadata is reported".to_owned()
    })?;
    validate_git_oid("EWB_BUILD_VCS_COMMIT", &commit)?;
    validate_git_oid("EWB_BUILD_VCS_TREE", &tree)?;
    if commit.len() != tree.len() {
        return Err(
            "builder-recorded commit and tree must use the same Git object format".to_owned(),
        );
    }
    let dirty = match dirty.as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("EWB_BUILD_VCS_DIRTY must be exactly true or false".to_owned()),
    };
    if let Some(tag) = tag.as_deref() {
        validate_git_tag(tag)?;
        if dirty {
            return Err("EWB_BUILD_VCS_TAG cannot be reported for a dirty VCS base".to_owned());
        }
    }

    Ok(ValidatedBuildMetadata {
        commit: Some(commit),
        tree: Some(tree),
        dirty: Some(dirty),
        tag,
    })
}

fn validate_git_oid(name: &str, value: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{name} must be a lowercase 40- or 64-character Git object ID"
        ));
    }
    Ok(())
}

fn validate_git_tag(value: &str) -> Result<(), String> {
    let invalid_character = value
        .chars()
        .any(|character| character.is_control() || " ~^:?*[\\".contains(character));
    let invalid_component = value.split('/').any(|component| {
        component.is_empty() || component.starts_with('.') || component.ends_with(".lock")
    });
    if value.chars().count() > 128
        || value == "@"
        || value.ends_with('.')
        || value.contains("..")
        || value.contains("@{")
        || invalid_character
        || invalid_component
    {
        return Err(
            "EWB_BUILD_VCS_TAG must be one valid Git tag name of at most 128 characters".to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn absent_metadata_is_explicitly_unreported() {
        let metadata = validate(None, None, None, None).unwrap();
        assert_eq!(metadata.commit, None);
        assert_eq!(metadata.tree, None);
        assert_eq!(metadata.dirty, None);
        assert_eq!(metadata.tag, None);
    }

    #[test]
    fn partial_metadata_is_rejected() {
        assert!(validate(Some(SHA1.to_owned()), None, None, None).is_err());
        assert!(validate(None, None, None, Some("v0.2.0".to_owned())).is_err());
    }

    #[test]
    fn mixed_git_object_formats_are_rejected() {
        assert!(
            validate(
                Some(SHA1.to_owned()),
                Some(SHA256.to_owned()),
                Some("false".to_owned()),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn dirty_or_invalid_exact_tags_are_rejected() {
        assert!(
            validate(
                Some(SHA1.to_owned()),
                Some(SHA1.to_owned()),
                Some("true".to_owned()),
                Some("v0.2.0".to_owned()),
            )
            .is_err()
        );
        assert!(
            validate(
                Some(SHA1.to_owned()),
                Some(SHA1.to_owned()),
                Some("false".to_owned()),
                Some("bad tag".to_owned()),
            )
            .is_err()
        );
    }
}
