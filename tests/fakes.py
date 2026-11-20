"""A scripted fake LLM, so agent wiring can be tested offline with no API calls.

The fake returns pre-written responses in order (a tool call, then another,
then the final answer) and records every request it received. That lets
tests check what ADK sent back to the model, e.g. that tool results were fed
in as observations.
"""

from __future__ import annotations

from typing import Any, AsyncGenerator, Callable

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import Field

Step = LlmResponse | Callable[[LlmRequest], LlmResponse]


class ScriptedLlm(BaseLlm):
    model: str = "scripted"
    script: list[Any] = Field(default_factory=list)
    requests: list[Any] = Field(default_factory=list)

    @classmethod
    def supported_models(cls) -> list[str]:
        return ["scripted"]

    async def generate_content_async(self, llm_request: LlmRequest,
                                     stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        self.requests.append(llm_request)
        index = len(self.requests) - 1
        if index >= len(self.script):
            raise AssertionError(f"ScriptedLlm ran out of scripted steps at call {index + 1}")
        step = self.script[index]
        yield step(llm_request) if callable(step) else step


def usage(input_tokens: int = 100, output_tokens: int = 20) -> types.GenerateContentResponseUsageMetadata:
    return types.GenerateContentResponseUsageMetadata(
        prompt_token_count=input_tokens, candidates_token_count=output_tokens,
        total_token_count=input_tokens + output_tokens)


def call(name: str, **args: Any) -> LlmResponse:
    """A model turn that requests one tool call."""
    return LlmResponse(
        content=types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))]),
        usage_metadata=usage())


def say(text: str) -> LlmResponse:
    """A model turn that is plain text."""
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]), usage_metadata=usage())


def function_responses(request: LlmRequest) -> list[types.FunctionResponse]:
    """Tool results ADK included in a request (the 'observations' in ReAct)."""
    return [p.function_response for c in request.contents or [] for p in c.parts or [] if p.function_response]
