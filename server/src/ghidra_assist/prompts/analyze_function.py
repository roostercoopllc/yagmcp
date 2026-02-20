"""MCP prompt: analyze_function

Generates a detailed analysis of a decompiled function, explaining what it
does, its parameters, return value, and any notable patterns.
"""

from __future__ import annotations

from dataclasses import dataclass
from textwrap import dedent

from ghidra_assist.prompts import register_prompt


@dataclass
class AnalyzeFunctionPrompt:
    """Prompt template for function analysis."""

    name: str = "analyze_function"
    description: str = (
        "Analyze a decompiled function — explain purpose, parameters, "
        "return value, and notable patterns."
    )

    def render(
        self,
        function_name: str,
        decompilation: str,
        program_name: str = "",
        additional_context: str = "",
    ) -> str:
        """Render the analysis prompt.

        Args:
            function_name: Name of the function being analyzed.
            decompilation: Decompiled pseudo-C source code.
            program_name: Optional program/binary name for context.
            additional_context: Optional extra context (e.g., calling
                convention, known struct definitions).

        Returns:
            Fully rendered prompt string.
        """
        header = f"Analyze the following decompiled function `{function_name}`"
        if program_name:
            header += f" from program `{program_name}`"
        header += "."

        context_block = ""
        if additional_context:
            context_block = dedent(f"""
                ## Additional Context
                {additional_context}
            """).strip() + "\n\n"

        return dedent(f"""
            {header}

            ## Decompiled Source
            ```c
            {decompilation}
            ```

            {context_block}## Instructions
            Provide a thorough analysis covering:

            1. **Purpose**: What does this function do? Summarize in one sentence,
               then elaborate.
            2. **Parameters**: Describe each parameter — likely type, purpose, and
               any constraints.
            3. **Return Value**: What does the function return and under what
               conditions?
            4. **Control Flow**: Describe the main execution paths, loops, and
               branches.
            5. **Notable Patterns**: Identify any common patterns such as:
               - Error handling (return codes, errno checks)
               - Memory management (malloc/free, buffer operations)
               - String operations
               - Cryptographic or hashing routines
               - Network/socket operations
               - File I/O
            6. **Suggested Name**: If the current name is generic (e.g., FUN_00401234),
               suggest a more descriptive name based on your analysis.
        """).strip() + "\n"


# Register the prompt at import time
PROMPT = register_prompt(AnalyzeFunctionPrompt())
