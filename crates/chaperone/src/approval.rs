//! The approval channel (`docs/design.md` 5.3): the effect plugin in the
//! approval channel slot, asked once per gate through its `approve` tool.

use chaperone_core::{APPROVE_TOOL, ApprovalRequest, GateAnswer};

use crate::effect::{Effect, EffectFault, Redactor};

/// Why the approval channel gave no answer. The gate is then denied for
/// its life (G2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalFault {
    /// The plugin is not running, or its connection is closed.
    NotConnected,
    /// The plugin answered with something that is not an answer.
    BadAnswer,
}

/// The approval channel plugin, as the call path asks it.
#[derive(Debug)]
pub struct ApprovalChannel {
    plugin: Box<dyn Effect>,
}

impl ApprovalChannel {
    /// Wrap the plugin of the approval channel slot. The host checked at
    /// start that it lists [`APPROVE_TOOL`].
    #[must_use]
    pub fn new(plugin: Box<dyn Effect>) -> Self {
        Self { plugin }
    }

    /// Ask the channel about one gate. The caller bounds the wait.
    ///
    /// # Errors
    ///
    /// Returns an [`ApprovalFault`] when no answer of the right shape came.
    pub async fn ask(
        &self,
        request: &ApprovalRequest<'_>,
        redactor: &Redactor,
    ) -> Result<GateAnswer, ApprovalFault> {
        let tool = chaperone_core::ToolName::try_new(APPROVE_TOOL)
            .map_err(|_| ApprovalFault::BadAnswer)?;
        let result = self
            .plugin
            .call(request.app, &tool, request.arguments())
            .await
            .map_err(|fault| match fault {
                EffectFault::NotConnected => ApprovalFault::NotConnected,
                EffectFault::BadResult => ApprovalFault::BadAnswer,
            })?;
        if result.is_error == Some(true) || result.content.len() != 1 {
            return Err(ApprovalFault::BadAnswer);
        }
        let text = result
            .content
            .first()
            .and_then(|block| block.as_text())
            .ok_or(ApprovalFault::BadAnswer)?;
        GateAnswer::read(text.text.as_bytes()).map_err(|error| {
            tracing::warn!(error = %redactor.blank(&error.to_string()), "the approval channel gave no answer");
            ApprovalFault::BadAnswer
        })
    }
}
