import mistune
from typing import List, Dict, Any, Optional, Tuple

# Try to import plugin_url, but provide a fallback if it doesn't exist
try:
    from mistune.plugins import plugin_url
    print("Successfully imported plugin_url from mistune.plugins")
except ImportError:
    print("WARNING: plugin_url not found in mistune.plugins. Using fallback implementation.")
    # Define a simple fallback plugin that does nothing
    def plugin_url(md):
        """Fallback implementation of plugin_url"""
        print("Using fallback plugin_url implementation")
        return md

class MarkdownParseError(Exception):
    pass

class MarkdownParser:
    def __init__(self):
        self._md = mistune.create_markdown(plugins=[plugin_url])

    def parse(self, text: str) -> Dict[str, Any]:
        try:
            ast = self._md(text, ast_plugin=True)
            return self._extract_components(ast)
        except Exception as e:
            raise MarkdownParseError(f"Failed to parse markdown: {e}")

    def _extract_components(self, ast: List[Dict[str, Any]]) -> Dict[str, Any]:
        code_blocks = []
        urls = set()
        references = set()
        structure = []
        normalized = []

        def walk(node, parent_type=None):
            if isinstance(node, dict):
                t = node.get("type")
                if t == "block_code":
                    code_blocks.append({
                        "language": node.get("info") or "text",
                        "code": node.get("text", "")
                    })
                elif t == "link":
                    urls.add(node.get("link", ""))
                elif t == "image":
                    urls.add(node.get("src", ""))
                elif t == "footnote_ref":
                    references.add(node.get("key", ""))
                elif t in ("heading", "list", "list_item"):
                    structure.append({
                        "type": t,
                        "level": node.get("level"),
                        "text": node.get("text", "")
                    })
                normalized.append({
                    "type": t,
                    "text": node.get("text", ""),
                    "children": []
                })
                for child in node.get("children", []):
                    walk(child, t)
            elif isinstance(node, list):
                for item in node:
                    walk(item, parent_type)

        walk(ast)
        return {
            "code_blocks": code_blocks,
            "urls": list(urls),
            "references": list(references),
            "structure": structure,
            "normalized": normalized
        }

def extract_markdown_components(text: str) -> Dict[str, Any]:
    parser = MarkdownParser()
    return parser.parse(text)