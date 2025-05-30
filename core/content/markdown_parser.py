import mistune
from typing import List, Dict, Any, Optional

# plugin_url is not typically needed for basic AST parsing with mistune v2/v3
# Standard links, images are part of the core AST.

class MarkdownParseError(Exception):
    """Custom exception for markdown parsing errors."""
    pass

class MarkdownParser:
    def __init__(self):
        # Initialize mistune in raw AST mode for code block extraction
        self._md = mistune.create_markdown(renderer=None)

    def parse(self, text: str) -> Dict[str, Any]:
        """
        Parses markdown text and extracts various components.
        Returns a dictionary containing code blocks, URLs, references,
        a structural overview, and a normalized content tree.
        """
        try:
            # Use md.parse() to get the AST
            ast = self._md.parse(text)
            if ast is None: # Handle cases where parsing might return None for empty/invalid input
                ast_nodes = []
            else:
                # Extract the nodes list from the AST tuple
                ast_nodes = ast[0] if isinstance(ast, tuple) and len(ast) > 0 else ast
            
            print("Mistune AST:", ast)  # Debug log
            return self._extract_components(ast_nodes, text)  # Pass only the nodes list
        except Exception as e:
            # Catching a broader exception from mistune if parse itself fails
            raise MarkdownParseError(f"Failed to parse markdown AST: {e}")

    def _extract_components(self, ast_nodes: List[Dict[str, Any]], original_text: str) -> Dict[str, Any]:
        """
        Extracts components from the mistune AST.
        
        Args:
            ast_nodes: The AST nodes from mistune
            original_text: The original markdown text for line number calculation
        """
        code_blocks: List[Dict[str, str]] = []
        urls: set[str] = set()
        references: set[str] = set()

        def get_node_text_content(node: Dict[str, Any]) -> str:
            """Helper to extract text from a node, potentially from its children."""
            if "text" in node: # Direct text (e.g., for 'text' type nodes, or simple headings)
                return node["text"]
            
            # For container nodes, concatenate text from children
            text_parts: List[str] = []
            if "children" in node:
                for child in node["children"]:
                    if child.get("type") == "text":
                        text_parts.append(child.get("text", ""))
                    # Could recurse here if deeper text aggregation is needed,
                    # but for simple structural text, direct children are often enough.
            return "".join(text_parts)


        def walk_and_collect(current_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
            """
            Recursively walks the AST, collects specific components,
            and builds a normalized hierarchical representation.
            """
            processed_nodes: List[Dict[str, Any]] = []
            for node in current_nodes:
                if not isinstance(node, dict):
                    continue

                node_type = node.get("type")
                
                # Initialize the representation for the current node
                node_repr: Dict[str, Any] = {
                    "type": node_type,
                    "raw_text": node.get("raw", ""), # Raw text if available (e.g. code blocks in some mistune versions)
                    "children": [],
                }
                # Attempt to get meaningful text for the node
                node_repr["text"] = get_node_text_content(node)


                # Component-specific extraction
                if node_type == "block_code":  # Mistune uses 'block_code' for code blocks
                    print("Found code block node:", node)  # Debug log
                    lang_info = node.get("attrs", {}).get("info")  # Language info is in attrs.info
                    language = lang_info.strip() if lang_info else "text"
                    code_content = node.get("raw", "")  # Code content is in raw field


                    # Find the code block in the original text to get line numbers
                    # Look for the opening fence with language
                    fence_pattern = f"```{language}"
                    code_block_pos = original_text.find(fence_pattern)
                    if code_block_pos == -1:  # Try without language
                        code_block_pos = original_text.find("```")
                    
                    # Calculate line numbers
                    lines_before = original_text[:code_block_pos].count('\n') + 1
                    lines_after = lines_before + code_content.count('\n') + 2  # +2 for the fence lines
                    
                    # Extract context (3 lines before and after)
                    text_lines = original_text.split('\n')
                    context_before = '\n'.join(text_lines[max(0, lines_before-4):lines_before-1]) if lines_before > 1 else ''
                    context_after = '\n'.join(text_lines[lines_after:min(len(text_lines), lines_after+3)])
                    
                    code_blocks.append({
                        "language": language,
                        "code": code_content,
                        "line_start": lines_before,
                        "line_end": lines_after - 1,  # -1 because line_end should be the last line of code
                        "context_before": context_before,
                        "context_after": context_after
                    })
                    node_repr["language"] = language
                    node_repr["code_content"] = code_content # Store in normalized as well
                
                elif node_type == "link":
                    url = node.get("link", "")
                    urls.add(url)
                    node_repr["url"] = url
                    # Text of the link is usually in its children
                    # get_node_text_content should handle this via children processing.

                elif node_type == "image":
                    src = node.get("src", "")
                    urls.add(src)
                    node_repr["src"] = src
                    node_repr["alt"] = node.get("alt", "")

                elif node_type == "footnote_ref":
                    key = node.get("key", "")
                    references.add(key)
                    node_repr["key"] = key
                
                elif node_type == "heading":
                    node_repr["level"] = node.get("level")
                    # Text for heading is handled by get_node_text_content

                # Recursively process children
                if "children" in node and isinstance(node["children"], list):
                    node_repr["children"] = walk_and_collect(node["children"])
                
                processed_nodes.append(node_repr)
            
            return processed_nodes

        normalized_content_tree = walk_and_collect(ast_nodes)

        # Build the flat 'structure' list from the hierarchical normalized_content_tree
        # This maintains compatibility if other parts of the system expect this flat structure.
        doc_structure: List[Dict[str, Any]] = []
        def build_flat_structure_list(nodes_list: List[Dict[str, Any]]):
            for item in nodes_list:
                item_type = item.get("type")
                if item_type in ("heading", "list", "list_item"): # Assuming 'list' and 'list_item' are types from mistune
                    struct_item: Dict[str, Any] = {"type": item_type}
                    if "level" in item: # For headings
                        struct_item["level"] = item["level"]
                    
                    # Extract text for the structural item
                    # For headings, item["text"] should be populated by get_node_text_content
                    # For lists/list_items, text might be more complex (concatenation of children's text)
                    struct_item["text"] = item.get("text", "") # Uses the text already processed for normalized_content
                    doc_structure.append(struct_item)
                
                if "children" in item:
                    build_flat_structure_list(item["children"])
        
        build_flat_structure_list(normalized_content_tree)

        return {
            "code_blocks": code_blocks,
            "urls": sorted(list(urls)), # Sort for consistent output
            "references": sorted(list(references)), # Sort for consistent output
            "structure": doc_structure,
            "normalized_content": normalized_content_tree # Hierarchical representation
        }

def extract_markdown_components(text: str) -> Dict[str, Any]:
    """Convenience function to parse markdown text and extract components."""
    parser = MarkdownParser()
    return parser.parse(text)