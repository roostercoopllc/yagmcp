"""MCP prompt: rename_suggestions

Generates meaningful name suggestions for auto-generated Ghidra symbols
(functions, variables, parameters) based on the decompiled source.
"""

from __future__ import annotations

from dataclasses import dataclass
from textwrap import dedent

from ghidra_assist.prompts import register_prompt


@dataclass
class RenameSuggestionsPrompt:
    """Prompt template for suggesting meaningful symbol names."""

    name: str = "rename_suggestions"
    description: str = (
        "Suggest meaningful names for auto-generated Ghidra symbols — "
        "functions, variables, and parameters."
    )

    def render(
        self,
        function_name: str,
        decompilation: str,
        program_name: str = "",
        known_types: str = "",
    ) -> str:
        """Render the rename suggestions prompt.

        Args:
            function_name: Current name of the function (often auto-generated
                like FUN_00401234).
            decompilation: Decompiled pseudo-C source code.
            program_name: Optional program/binary name for context.
            known_types: Optional known data type definitions or struct layouts
                that may help with naming.

        Returns:
            Fully rendered prompt string.
        """
        header = (
            f"Suggest meaningful names for the auto-generated symbols in the "
            f"decompiled function `{function_name}`"
        )
        if program_name:
            header += f" from program `{program_name}`"
        header += "."

        types_block = ""
        if known_types:
            types_block = dedent(f"""
                ## Known Data Types
                ```c
                {known_types}
                ```
            """).strip() + "\n\n"

        return dedent(f"""
            {header}

            ## Decompiled Source
            ```c
            {decompilation}
            ```

            {types_block}## Instructions
            Analyze the decompiled code and suggest better names for all
            auto-generated symbols. Follow these guidelines:

            ### Naming Conventions
            - Use `snake_case` for functions and local variables.
            - Use `camelCase` if the binary appears to be C++ with that convention.
            - Use descriptive names that convey purpose, not implementation.
            - Prefix boolean variables/parameters with `is_`, `has_`, `can_`, etc.
            - Use standard abbreviations where conventional (e.g., `buf`, `len`,
              `ctx`, `fd`, `ptr`).

            ### Output Format
            Return a structured list grouped by symbol type:

            **Function Name:**
            | Current | Suggested | Rationale |
            |---------|-----------|-----------|
            | {function_name} | <suggestion> | <why> |

            **Parameters:**
            | Current | Suggested Type | Suggested Name | Rationale |
            |---------|---------------|----------------|-----------|
            | param_1 | <type> | <name> | <why> |

            **Local Variables:**
            | Current | Suggested Type | Suggested Name | Rationale |
            |---------|---------------|----------------|-----------|
            | local_10 | <type> | <name> | <why> |

            ### Guidelines
            - Only suggest renames for clearly auto-generated names (FUN_, DAT_,
              param_, local_, uVar, iVar, etc.).
            - If a name is already meaningful, note it as "keep as-is".
            - Base suggestions on observed usage patterns, string references,
              API calls, and control flow.
            - When uncertain, provide 2-3 alternatives ranked by confidence.
        """).strip() + "\n"


# Register the prompt at import time
PROMPT = register_prompt(RenameSuggestionsPrompt())
