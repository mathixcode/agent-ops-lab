"""OpenTelemetry GenAI semantic conventions — PINNED (spec B.3: "pin a version").

These conventions are still in development and attribute names move between releases, so
the names are fixed here against one release instead of being imported from whatever
`opentelemetry-semantic-conventions` happens to be installed. An acceptance check compares
this table with the installed package and fails if they have drifted apart.
"""

SEMCONV_VERSION = "1.45.0"
SCHEMA_URL = f"https://opentelemetry.io/schemas/{SEMCONV_VERSION}"

# gen_ai.* attribute names used by the defender
GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
GEN_AI_PROVIDER_NAME = "gen_ai.provider.name"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"
GEN_AI_CONVERSATION_ID = "gen_ai.conversation.id"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"
GEN_AI_TOOL_TYPE = "gen_ai.tool.type"
GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
ERROR_TYPE = "error.type"

# well-known values
OPERATION_EXECUTE_TOOL = "execute_tool"
OPERATION_INVOKE_AGENT = "invoke_agent"
PROVIDER_ANTHROPIC = "anthropic"
TOOL_TYPE_FUNCTION = "function"

GEN_AI_ATTRIBUTES = (GEN_AI_OPERATION_NAME, GEN_AI_PROVIDER_NAME, GEN_AI_AGENT_NAME, GEN_AI_CONVERSATION_ID,
                     GEN_AI_REQUEST_MODEL, GEN_AI_TOOL_NAME, GEN_AI_TOOL_CALL_ID, GEN_AI_TOOL_TYPE,
                     GEN_AI_USAGE_INPUT_TOKENS, GEN_AI_USAGE_OUTPUT_TOKENS)

# Lab-specific attributes carrying the spec 1.3 event (not part of the GenAI conventions).
LAB_RUN_ID = "lab.run_id"
LAB_EVENT_TYPE = "lab.event.type"
LAB_EVENT_SEQ = "lab.event.seq"
LAB_EVENT_TS = "lab.event.ts"
LAB_EVENT_PAYLOAD = "lab.event.payload"
LANGFUSE_SESSION_ID = "langfuse.session.id"
